const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '12mb' }));

const env = process.env;
const SERVICE_JSON = env.FIREBASE_SERVICE_ACCOUNT_JSON;
if (!admin.apps.length) {
  if (!SERVICE_JSON) throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_JSON');
  let creds;
  try { creds = JSON.parse(SERVICE_JSON); } catch { throw new Error('Invalid FIREBASE_SERVICE_ACCOUNT_JSON'); }
  admin.initializeApp({ credential: admin.credential.cert(creds) });
}
const db = admin.firestore();
const FV = admin.firestore.FieldValue;
const SECRET = env.SESSION_SECRET || '';
const ADMIN_USERNAME = (env.ADMIN_USERNAME || '').trim().toLowerCase();
const ADMIN_PASSWORD = env.ADMIN_PASSWORD || '';

const clean = (v, max = 1000) => String(v ?? '').trim().slice(0, max);
const normalizeUsername = (v) => clean(v, 24).toLowerCase().replace(/[^a-z0-9_.-]/g, '');
const nowIso = () => new Date().toISOString();

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(String(password), salt, 64, (err, key) => err ? reject(err) : resolve(`${salt}:${key.toString('hex')}`)));
}
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const [salt, hex] = String(stored || '').split(':');
    if (!salt || !hex) return resolve(false);
    crypto.scrypt(String(password), salt, 64, (err, key) => {
      if (err) return reject(err);
      const a = Buffer.from(hex, 'hex');
      resolve(a.length === key.length && crypto.timingSafeEqual(a, key));
    });
  });
}
function parseCookies(req) {
  const out = {};
  for (const pair of String(req.headers.cookie || '').split(';')) {
    const i = pair.indexOf('=');
    if (i < 0) continue;
    out[pair.slice(0, i).trim()] = decodeURIComponent(pair.slice(i + 1).trim());
  }
  return out;
}
function signSession(payload) { return crypto.createHmac('sha256', SECRET).update(payload).digest('hex'); }
function setSession(res, id, days = 30) {
  const exp = Date.now() + days * 86400000;
  const payload = `${id}.${exp}`;
  res.setHeader('Set-Cookie', `bw_session=${encodeURIComponent(`${payload}.${signSession(payload)}`)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${days * 86400}`);
}
function clearSession(res) { res.setHeader('Set-Cookie', 'bw_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'); }
function currentId(req) {
  if (!SECRET) return null;
  const raw = parseCookies(req).bw_session || '';
  const [id, exp, sig] = raw.split('.');
  if (!id || !exp || !sig || Number(exp) < Date.now()) return null;
  const expected = signSession(`${id}.${exp}`);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  return id;
}
async function getUser(id) {
  if (!id) return null;
  const snap = await db.collection('users').doc(id).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}
function safeUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    displayName: u.displayName || u.username,
    bio: u.bio || '',
    avatarUrl: u.avatarUrl || '',
    coverUrl: u.coverUrl || '',
    followersCount: Number(u.followersCount || 0),
    followingCount: Number(u.followingCount || 0),
    createdAt: u.createdAt || null,
  };
}
async function requireUser(req, res, next) {
  try {
    const user = await getUser(currentId(req));
    if (!user) return res.status(401).json({ error: 'Login required.' });
    req.user = user;
    next();
  } catch (e) { res.status(500).json({ error: e.message }); }
}
async function requireAdmin(req, res, next) {
  try {
    const id = currentId(req);
    if (id === '__admin__' && ADMIN_USERNAME && ADMIN_PASSWORD) { req.user = { id: '__admin__', username: ADMIN_USERNAME, displayName: 'Administrator' }; return next(); }
    const user = await getUser(id);
    if (!user || !ADMIN_USERNAME || user.username !== ADMIN_USERNAME) return res.status(403).json({ error: 'Admin access required.' });
    req.user = user;
    next();
  } catch (e) { res.status(500).json({ error: e.message }); }
}
async function notify(userId, actorId, type, text, postId = '') {
  if (!userId || !actorId || userId === actorId) return;
  await db.collection('notifications').add({ userId, actorId, type, text, postId, read: false, createdAt: FV.serverTimestamp() });
}
async function uploadToImgBB(data) {
  const key = env.IMGBB_API_KEY;
  if (!key) throw new Error('IMGBB_API_KEY is not configured.');
  const raw = String(data || '').replace(/^data:image\/(?:jpeg|jpg|png|webp|gif);base64,/i, '').replace(/\s/g, '');
  if (!raw) throw new Error('Invalid image.');
  const form = new FormData();
  form.append('key', key);
  form.append('image', raw);
  const r = await fetch('https://api.imgbb.com/1/upload', { method: 'POST', body: form });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.success) throw new Error(d.error?.message || 'Image upload failed.');
  return { url: d.data.url, deleteUrl: d.data.delete_url || '' };
}
async function addAuthorAndViewerState(posts, viewerId) {
  const ids = [...new Set(posts.map(p => p.authorId).filter(Boolean))];
  const users = {};
  for (const id of ids) {
    const u = await getUser(id);
    if (u) users[id] = safeUser(u);
  }
  const out = [];
  for (const p of posts) {
    let liked = false, bookmarked = false;
    if (viewerId) {
      liked = (await db.collection('postLikes').doc(`${p.id}_${viewerId}`).get()).exists;
      bookmarked = (await db.collection('bookmarks').doc(`${viewerId}_${p.id}`).get()).exists;
    }
    out.push({ ...p, author: users[p.authorId] || null, liked, bookmarked });
  }
  return out;
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'BlueWave', firebaseConfigured: !!SERVICE_JSON, imgbbConfigured: !!env.IMGBB_API_KEY }));

app.get('/api/auth/me', async (req, res) => { try { res.json({ user: safeUser(await getUser(currentId(req))) }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/auth/register', async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || '');
    const displayName = clean(req.body.displayName, 60) || username;
    if (!/^[a-z0-9_.-]{3,24}$/.test(username)) throw new Error('Username must be 3–24 characters.');
    if (password.length < 6) throw new Error('Password must be at least 6 characters.');
    const ref = db.collection('users').doc(username);
    if ((await ref.get()).exists) throw new Error('Username already exists.');
    const passwordHash = await hashPassword(password);
    await ref.set({ username, displayName, bio: '', avatarUrl: '', coverUrl: '', followersCount: 0, followingCount: 0, passwordHash, createdAt: FV.serverTimestamp() });
    setSession(res, username);
    res.json({ ok: true, user: safeUser(await getUser(username)) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const user = await getUser(username);
    if (!user || !(await verifyPassword(req.body.password, user.passwordHash))) throw new Error('Invalid username or password.');
    setSession(res, username);
    res.json({ ok: true, user: safeUser(user) });
  } catch (e) { res.status(401).json({ error: e.message }); }
});
app.post('/api/auth/logout', (req, res) => { clearSession(res); res.json({ ok: true }); });
app.post('/api/admin/login', async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username), password = String(req.body.password || '');
    if (!ADMIN_USERNAME || !ADMIN_PASSWORD || username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) throw new Error('Invalid admin credentials.');
    setSession(res, '__admin__', 1);
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: e.message }); }
});

app.post('/api/media/upload', requireUser, async (req, res) => {
  try {
    const data = String(req.body.data || '');
    if (!/^data:image\/(jpeg|jpg|png|webp|gif);base64,/i.test(data)) throw new Error('Only JPG, PNG, WEBP or GIF images are supported.');
    if (data.length > 10 * 1024 * 1024) throw new Error('Image is too large.');
    res.json({ ok: true, ...(await uploadToImgBB(data)) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/profile/update', requireUser, async (req, res) => {
  try {
    const data = {
      displayName: clean(req.body.displayName, 60) || req.user.username,
      bio: clean(req.body.bio, 280),
      avatarUrl: clean(req.body.avatarUrl, 1200),
      coverUrl: clean(req.body.coverUrl, 1200),
    };
    await db.collection('users').doc(req.user.id).update(data);
    res.json({ ok: true, user: safeUser(await getUser(req.user.id)) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/feed', requireUser, async (req, res) => {
  try {
    const follows = await db.collection('follows').where('followerId', '==', req.user.id).get();
    const ids = [req.user.id, ...follows.docs.map(d => d.data().followingId)].slice(0, 30);
    const posts = [];
    for (let i = 0; i < ids.length; i += 10) {
      const group = ids.slice(i, i + 10);
      const s = await db.collection('posts').where('authorId', 'in', group).limit(100).get();
      s.docs.forEach(d => posts.push({ id: d.id, ...d.data() }));
    }
    posts.sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));
    res.json({ posts: await addAuthorAndViewerState(posts.slice(0, 80), req.user.id) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/explore', requireUser, async (req, res) => {
  try {
    const s = await db.collection('posts').limit(150).get();
    const posts = s.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));
    res.json({ posts: await addAuthorAndViewerState(posts.slice(0, 80), req.user.id) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/posts', requireUser, async (req, res) => {
  try {
    const text = clean(req.body.text, 1000);
    const imageUrl = clean(req.body.imageUrl, 1200);
    if (!text && !imageUrl) throw new Error('Write something or add a photo.');
    const ref = db.collection('posts').doc();
    await ref.set({ authorId: req.user.id, text, imageUrl, likesCount: 0, commentsCount: 0, createdAt: FV.serverTimestamp() });
    res.json({ ok: true, id: ref.id });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/posts/:id', requireUser, async (req, res) => {
  try {
    const ref = db.collection('posts').doc(req.params.id), p = await ref.get();
    if (!p.exists) throw new Error('Post not found.');
    if (p.data().authorId !== req.user.id) throw new Error('You can only delete your own post.');
    await ref.delete();
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/posts/:id/like', requireUser, async (req, res) => {
  try {
    const post = await db.collection('posts').doc(req.params.id).get();
    if (!post.exists) throw new Error('Post not found.');
    const ref = db.collection('postLikes').doc(`${req.params.id}_${req.user.id}`), exists = await ref.get();
    let liked;
    if (exists.exists) { await ref.delete(); await post.ref.update({ likesCount: FV.increment(-1) }); liked = false; }
    else { await ref.set({ postId: req.params.id, userId: req.user.id, createdAt: FV.serverTimestamp() }); await post.ref.update({ likesCount: FV.increment(1) }); liked = true; await notify(post.data().authorId, req.user.id, 'like', `${req.user.displayName} liked your post`, req.params.id); }
    const fresh = await post.ref.get();
    res.json({ ok: true, liked, likesCount: Math.max(0, Number(fresh.data().likesCount || 0)) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/posts/:id/comments', requireUser, async (req, res) => {
  try {
    const s = await db.collection('comments').where('postId', '==', req.params.id).limit(100).get();
    const rows = s.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => (a.createdAt?._seconds || 0) - (b.createdAt?._seconds || 0));
    const out = [];
    for (const c of rows) { const u = await getUser(c.userId); out.push({ ...c, author: safeUser(u) }); }
    res.json({ comments: out });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/posts/:id/comments', requireUser, async (req, res) => {
  try {
    const text = clean(req.body.text, 500);
    if (!text) throw new Error('Comment is empty.');
    const post = await db.collection('posts').doc(req.params.id).get();
    if (!post.exists) throw new Error('Post not found.');
    await db.collection('comments').add({ postId: req.params.id, userId: req.user.id, text, createdAt: FV.serverTimestamp() });
    await post.ref.update({ commentsCount: FV.increment(1) });
    await notify(post.data().authorId, req.user.id, 'comment', `${req.user.displayName} replied to your post`, req.params.id);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/posts/:id/bookmark', requireUser, async (req, res) => {
  try {
    const ref = db.collection('bookmarks').doc(`${req.user.id}_${req.params.id}`), snap = await ref.get();
    if (snap.exists) await ref.delete(); else await ref.set({ userId: req.user.id, postId: req.params.id, createdAt: FV.serverTimestamp() });
    res.json({ ok: true, bookmarked: !snap.exists });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/bookmarks', requireUser, async (req, res) => {
  try {
    const s = await db.collection('bookmarks').where('userId', '==', req.user.id).limit(100).get();
    const posts = [];
    for (const d of s.docs) { const p = await db.collection('posts').doc(d.data().postId).get(); if (p.exists) posts.push({ id: p.id, ...p.data() }); }
    posts.sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));
    res.json({ posts: await addAuthorAndViewerState(posts, req.user.id) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/search', requireUser, async (req, res) => {
  try {
    const q = clean(req.query.q, 40).toLowerCase();
    if (!q) return res.json({ users: [] });
    const s = await db.collection('users').orderBy('username').startAt(q).endAt(q + '\uf8ff').limit(20).get();
    res.json({ users: s.docs.map(d => safeUser({ id: d.id, ...d.data() })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/users/:username', requireUser, async (req, res) => {
  try {
    const id = normalizeUsername(req.params.username), u = await getUser(id);
    if (!u) return res.status(404).json({ error: 'User not found.' });
    const following = (await db.collection('follows').doc(`${req.user.id}_${id}`).get()).exists;
    res.json({ user: safeUser(u), following });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/users/:username/posts', requireUser, async (req, res) => {
  try {
    const id = normalizeUsername(req.params.username), s = await db.collection('posts').where('authorId', '==', id).limit(100).get();
    const posts = s.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));
    res.json({ posts: await addAuthorAndViewerState(posts, req.user.id) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/users/:username/follow', requireUser, async (req, res) => {
  try {
    const id = normalizeUsername(req.params.username);
    if (id === req.user.id) throw new Error('You cannot follow yourself.');
    const target = await getUser(id); if (!target) throw new Error('User not found.');
    const ref = db.collection('follows').doc(`${req.user.id}_${id}`), snap = await ref.get();
    if (snap.exists) {
      await ref.delete();
      await db.collection('users').doc(req.user.id).update({ followingCount: FV.increment(-1) });
      await db.collection('users').doc(id).update({ followersCount: FV.increment(-1) });
      res.json({ ok: true, following: false });
    } else {
      await ref.set({ followerId: req.user.id, followingId: id, createdAt: FV.serverTimestamp() });
      await db.collection('users').doc(req.user.id).update({ followingCount: FV.increment(1) });
      await db.collection('users').doc(id).update({ followersCount: FV.increment(1) });
      await notify(id, req.user.id, 'follow', `${req.user.displayName} started following you`);
      res.json({ ok: true, following: true });
    }
  } catch (e) { res.status(400).json({ error: e.message }); }
});
async function listPeople(usernameId, mode) {
  const q = mode === 'followers' ? { field: 'followingId', value: usernameId } : { field: 'followerId', value: usernameId };
  const s = await db.collection('follows').where(q.field, '==', q.value).limit(100).get();
  const ids = s.docs.map(d => mode === 'followers' ? d.data().followerId : d.data().followingId);
  const out = []; for (const id of ids) { const u = await getUser(id); if (u) out.push(safeUser(u)); }
  return out;
}
app.get('/api/users/:username/followers', requireUser, async (req, res) => { try { res.json({ users: await listPeople(normalizeUsername(req.params.username), 'followers') }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/users/:username/following', requireUser, async (req, res) => { try { res.json({ users: await listPeople(normalizeUsername(req.params.username), 'following') }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/suggestions', requireUser, async (req, res) => {
  try {
    const f = await db.collection('follows').where('followerId', '==', req.user.id).get();
    const excluded = new Set([req.user.id, ...f.docs.map(d => d.data().followingId)]);
    const s = await db.collection('users').limit(40).get();
    res.json({ users: s.docs.map(d => safeUser({ id: d.id, ...d.data() })).filter(u => !excluded.has(u.id)).slice(0, 8) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/trending', requireUser, async (req, res) => {
  try {
    const s = await db.collection('posts').limit(250).get(), counts = {};
    for (const d of s.docs) for (const tag of String(d.data().text || '').match(/#[a-z0-9_]+/gi) || []) counts[tag.toLowerCase()] = (counts[tag.toLowerCase()] || 0) + 1;
    res.json({ trends: Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([tag, count]) => ({ tag, count })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/notifications', requireUser, async (req, res) => {
  try {
    const s = await db.collection('notifications').where('userId', '==', req.user.id).limit(100).get();
    const rows = s.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));
    const out = []; for (const n of rows) { const u = await getUser(n.actorId); out.push({ ...n, actor: safeUser(u) }); }
    res.json({ notifications: out, unread: rows.filter(x => !x.read).length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/notifications/read', requireUser, async (req, res) => {
  try { const s = await db.collection('notifications').where('userId', '==', req.user.id).where('read', '==', false).limit(100).get(); await Promise.all(s.docs.map(d => d.ref.update({ read: true }))); res.json({ ok: true }); } catch (e) { res.status(400).json({ error: e.message }); }
});

function conversationId(a, b) { return [a, b].sort().join('__'); }
app.get('/api/messages', requireUser, async (req, res) => {
  try {
    const s = await db.collection('conversations').where('participants', 'array-contains', req.user.id).limit(50).get();
    const out = [];
    for (const d of s.docs) { const data = d.data(), other = (data.participants || []).find(x => x !== req.user.id), u = await getUser(other); if (u) out.push({ id: d.id, lastMessage: data.lastMessage || '', updatedAt: data.updatedAt || null, user: safeUser(u) }); }
    out.sort((a, b) => (b.updatedAt?._seconds || 0) - (a.updatedAt?._seconds || 0)); res.json({ conversations: out });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/messages/:username', requireUser, async (req, res) => {
  try {
    const u = await getUser(normalizeUsername(req.params.username)); if (!u) return res.status(404).json({ error: 'User not found.' });
    const c = await db.collection('conversations').doc(conversationId(req.user.id, u.id)).get();
    if (!c.exists) return res.json({ user: safeUser(u), messages: [] });
    const s = await c.ref.collection('messages').limit(150).get();
    const messages = s.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => (a.createdAt?._seconds || 0) - (b.createdAt?._seconds || 0));
    res.json({ user: safeUser(u), messages });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/messages/:username', requireUser, async (req, res) => {
  try {
    const u = await getUser(normalizeUsername(req.params.username)); if (!u) return res.status(404).json({ error: 'User not found.' });
    const text = clean(req.body.text, 2000), imageUrl = clean(req.body.imageUrl, 1200); if (!text && !imageUrl) throw new Error('Message is empty.');
    const cid = conversationId(req.user.id, u.id), c = db.collection('conversations').doc(cid);
    await c.set({ participants: [req.user.id, u.id], lastMessage: text || '📷 Photo', updatedAt: FV.serverTimestamp() }, { merge: true });
    await c.collection('messages').add({ senderId: req.user.id, receiverId: u.id, text, imageUrl, createdAt: FV.serverTimestamp() });
    await notify(u.id, req.user.id, 'message', `${req.user.displayName} sent you a message`);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Admin
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [u, p, f, n] = await Promise.all([db.collection('users').get(), db.collection('posts').get(), db.collection('follows').get(), db.collection('notifications').get()]);
    res.json({ users: u.size, posts: p.size, follows: f.size, notifications: n.size });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try { const s = await db.collection('users').orderBy('createdAt', 'desc').limit(200).get(); res.json({ users: s.docs.map(d => safeUser({ id: d.id, ...d.data() })) }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/users/:username/toggle-verify', requireAdmin, async (req, res) => {
  try { const ref = db.collection('users').doc(normalizeUsername(req.params.username)), u = await ref.get(); if (!u.exists) throw new Error('User not found.'); await ref.update({ verified: !u.data().verified }); res.json({ ok: true, verified: !u.data().verified }); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/admin/users/:username/toggle-ban', requireAdmin, async (req, res) => {
  try { const ref = db.collection('users').doc(normalizeUsername(req.params.username)), u = await ref.get(); if (!u.exists) throw new Error('User not found.'); await ref.update({ banned: !u.data().banned }); res.json({ ok: true, banned: !u.data().banned }); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/admin/posts/:id', requireAdmin, async (req, res) => { try { await db.collection('posts').doc(req.params.id).delete(); res.json({ ok: true }); } catch (e) { res.status(400).json({ error: e.message }); } });
app.get('/api/admin/posts', requireAdmin, async (req, res) => {
  try { const s = await db.collection('posts').limit(200).get(); const posts = s.docs.map(d => ({ id: d.id, ...d.data() })); posts.sort((a,b)=>(b.createdAt?._seconds||0)-(a.createdAt?._seconds||0)); res.json({ posts: await addAuthorAndViewerState(posts, null) }); } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/{*splat}', (req, res, next) => { if (req.path.startsWith('/api/')) return next(); res.sendFile(require('path').join(process.cwd(), 'index.html')); });

module.exports = app;
