const express = require('express');
const crypto = require('crypto');
const multer = require('multer');
const { getApps, initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

function env(name) { return process.env[name] || ''; }
function getFirebaseApp() {
  if (getApps().length) return getApps()[0];
  const raw = env('FIREBASE_SERVICE_ACCOUNT_JSON');
  if (raw) {
    let svc;
    try { svc = JSON.parse(raw); } catch { throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is invalid JSON'); }
    if (!svc.private_key || typeof svc.private_key !== 'string') throw new Error('Firebase service account is missing private_key');
    return initializeApp({ credential: cert(svc) });
  }
  const privateKey = env('FIREBASE_PRIVATE_KEY').replace(/\\n/g, '\n');
  if (env('FIREBASE_PROJECT_ID') && env('FIREBASE_CLIENT_EMAIL') && privateKey) {
    return initializeApp({ credential: cert({ projectId: env('FIREBASE_PROJECT_ID'), clientEmail: env('FIREBASE_CLIENT_EMAIL'), privateKey }) });
  }
  throw new Error('Firebase service account is not configured');
}
let db;
function firestore() { if (!db) db = getFirestore(getFirebaseApp()); return db; }

function send(res, status, body) { return res.status(status).json(body); }
function ok(res, data={}) { return send(res, 200, { ok: true, ...data }); }
function fail(res, message, status=400) { return send(res, status, { ok: false, error: message }); }

const COOKIE = 'bluewave_session';
function b64(s) { return Buffer.from(s).toString('base64url'); }
function sign(value) { return crypto.createHmac('sha256', env('SESSION_SECRET') || 'dev-secret').update(value).digest('base64url'); }
function makeSession(uid, role='user') {
  const payload = { uid, role, exp: Date.now() + 1000 * 60 * 60 * 24 * 14 };
  const body = b64(JSON.stringify(payload));
  return `${body}.${sign(body)}`;
}
function parseCookies(header='') { return Object.fromEntries(header.split(';').map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf('=');return i<0?[x,'']:[x.slice(0,i),decodeURIComponent(x.slice(i+1))]})); }
function currentSession(req) {
  const token = parseCookies(req.headers.cookie || '')[COOKIE];
  if (!token) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(body)))) return null;
  try { const p = JSON.parse(Buffer.from(body,'base64url').toString()); if (!p.exp || p.exp < Date.now()) return null; return p; } catch { return null; }
}
function setSession(res, uid, role='user') {
  const token = makeSession(uid, role);
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1209600${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
}
function clearSession(res) { res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`); }
async function requireUser(req, res) { const s = currentSession(req); if (!s || s.role !== 'user') { fail(res,'Please login',401); return null; } return s; }
async function requireAdmin(req,res) { const s=currentSession(req); if (!s || s.role!=='admin') { fail(res,'Admin only',403); return null; } return s; }

async function hashPassword(password, saltHex) {
  const salt = saltHex || crypto.randomBytes(16).toString('hex');
  const hash = await new Promise((resolve,reject)=>crypto.scrypt(password,salt,64,(e,d)=>e?reject(e):resolve(d.toString('hex'))));
  return { salt, hash };
}
async function verifyPassword(password, salt, expected) {
  const {hash}=await hashPassword(password,salt);
  return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(expected,'hex'));
}

app.get('/api/health', async (req,res)=>{
  try { firestore(); return ok(res,{service:'bluewave',firebaseConfigured:true,imgbbConfigured:Boolean(env('IMGBB_API_KEY'))}); }
  catch(e){ return fail(res,e.message,500); }
});

app.post('/api/auth/register', async (req,res)=>{
  try {
    const email=String(req.body.email||'').trim().toLowerCase();
    const username=String(req.body.username||'').trim().toLowerCase().replace(/[^a-z0-9_]/g,'').slice(0,24);
    const name=String(req.body.name||'').trim().slice(0,60);
    const password=String(req.body.password||'');
    if(!email.includes('@')||!username||!name||password.length<6) return fail(res,'Enter valid email, username, name and a 6+ character password');
    const users=firestore().collection('users');
    const existing=await users.where('email','==',email).limit(1).get();
    if(!existing.empty) return fail(res,'Email already registered',409);
    const byUser=await users.where('username','==',username).limit(1).get();
    if(!byUser.empty) return fail(res,'Username already taken',409);
    const {salt,hash}=await hashPassword(password);
    const ref=users.doc();
    const user={uid:ref.id,email,username,name,passwordHash:hash,passwordSalt:salt,photoURL:'',coverURL:'',bio:'',followersCount:0,followingCount:0,role:'user',createdAt:Date.now(),lastSeenAt:Date.now()};
    await ref.set(user); setSession(res,ref.id,'user'); return ok(res,{user:{...user,passwordHash:undefined,passwordSalt:undefined}});
  } catch(e){ return fail(res,e.message,500); }
});

app.post('/api/auth/login', async (req,res)=>{
  try {
    const email=String(req.body.email||'').trim().toLowerCase(); const password=String(req.body.password||'');
    const s=await firestore().collection('users').where('email','==',email).limit(1).get();
    if(s.empty) return fail(res,'Invalid email or password',401);
    const d=s.docs[0].data(); if(!await verifyPassword(password,d.passwordSalt,d.passwordHash)) return fail(res,'Invalid email or password',401);
    await s.docs[0].ref.update({lastSeenAt:Date.now()}); setSession(res,d.uid,'user'); return ok(res,{user:{...d,passwordHash:undefined,passwordSalt:undefined}});
  } catch(e){ return fail(res,e.message,500); }
});
app.post('/api/auth/logout',(req,res)=>{clearSession(res);return ok(res);});
app.get('/api/auth/me', async (req,res)=>{try{const s=currentSession(req);if(!s)return ok(res,{user:null});const d=await firestore().collection('users').doc(s.uid).get();if(!d.exists)return ok(res,{user:null});const u=d.data();return ok(res,{user:{...u,passwordHash:undefined,passwordSalt:undefined,uid:d.id}})}catch(e){return fail(res,e.message,500)}});

async function userDoc(uid){ const d=await firestore().collection('users').doc(uid).get(); return d.exists?{id:d.id,...d.data()}:null; }

app.get('/api/feed', async (req,res)=>{
  try {
    const s=currentSession(req); if(!s) return fail(res,'Please login',401);
    const me=await userDoc(s.uid); if(!me) return fail(res,'User not found',404);
    const following=await firestore().collection('users').doc(s.uid).collection('following').limit(200).get();
    const ids=new Set([s.uid,...following.docs.map(d=>d.id)]);
    const posts=await firestore().collection('posts').orderBy('createdAt','desc').limit(80).get();
    const data=[]; for(const d of posts.docs){const p={id:d.id,...d.data()}; if(ids.has(p.authorId) || req.query.mode==='explore'){
      const author=await userDoc(p.authorId); p.author=author?{uid:author.id,name:author.name,username:author.username,photoURL:author.photoURL}:null; data.push(p);
    }}
    return ok(res,{posts:data.slice(0,50)});
  }catch(e){return fail(res,e.message,500)}
});

app.post('/api/posts', async (req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const text=String(req.body.text||'').trim().slice(0,500);const imageURL=String(req.body.imageURL||'');if(!text&&!imageURL)return fail(res,'Post cannot be empty');const u=await userDoc(s.uid);const ref=firestore().collection('posts').doc();await ref.set({authorId:s.uid,text,imageURL,createdAt:Date.now(),likeCount:0,commentCount:0,shareCount:0});return ok(res,{post:{id:ref.id,author:{uid:s.uid,name:u.name,username:u.username,photoURL:u.photoURL},text,imageURL,createdAt:Date.now(),likeCount:0,commentCount:0,shareCount:0}})}catch(e){return fail(res,e.message,500)}});
app.delete('/api/posts/:id',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const ref=firestore().collection('posts').doc(req.params.id);const d=await ref.get();if(!d.exists)return fail(res,'Post not found',404);if(d.data().authorId!==s.uid)return fail(res,'Forbidden',403);await ref.delete();return ok(res)}catch(e){return fail(res,e.message,500)}});
app.post('/api/posts/:id/bookmark',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const r=firestore().collection('users').doc(s.uid).collection('bookmarks').doc(req.params.id);const x=await r.get();if(x.exists){await r.delete();return ok(res,{bookmarked:false})}await r.set({postId:req.params.id,createdAt:Date.now()});return ok(res,{bookmarked:true})}catch(e){return fail(res,e.message,500)}});
app.post('/api/posts/:id/share',async(req,res)=>{try{await firestore().collection('posts').doc(req.params.id).update({shareCount:FieldValue.increment(1)});return ok(res)}catch(e){return fail(res,e.message,500)}});

app.post('/api/posts/:id/like',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const p=firestore().collection('posts').doc(req.params.id);const l=p.collection('likes').doc(s.uid);const x=await l.get();if(x.exists){await l.delete();await p.update({likeCount:FieldValue.increment(-1)});return ok(res,{liked:false})}await l.set({createdAt:Date.now()});await p.update({likeCount:FieldValue.increment(1)});const pd=await p.get();if(pd.data()?.authorId!==s.uid)await firestore().collection('users').doc(pd.data().authorId).collection('notifications').doc().set({type:'like',postId:req.params.id,fromUserId:s.uid,createdAt:Date.now(),read:false});return ok(res,{liked:true})}catch(e){return fail(res,e.message,500)}});
app.post('/api/posts/:id/comments',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const text=String(req.body.text||'').trim().slice(0,500);if(!text)return fail(res,'Comment is empty');const u=await userDoc(s.uid);const p=firestore().collection('posts').doc(req.params.id);const r=p.collection('comments').doc();await r.set({userId:s.uid,userName:u.name,username:u.username,text,createdAt:Date.now()});await p.update({commentCount:FieldValue.increment(1)});return ok(res,{comment:{id:r.id,userName:u.name,username:u.username,text,createdAt:Date.now()}})}catch(e){return fail(res,e.message,500)}});
app.get('/api/posts/:id/comments',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const x=await firestore().collection('posts').doc(req.params.id).collection('comments').orderBy('createdAt','asc').limit(100).get();return ok(res,{comments:x.docs.map(d=>({id:d.id,...d.data()}))})}catch(e){return fail(res,e.message,500)}});

app.post('/api/users/:id/follow',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;if(req.params.id===s.uid)return fail(res,'Cannot follow yourself');const meRef=firestore().collection('users').doc(s.uid), targetRef=firestore().collection('users').doc(req.params.id);const t=await targetRef.get();if(!t.exists)return fail(res,'User not found',404);const f=targetRef.collection('followers').doc(s.uid), g=meRef.collection('following').doc(req.params.id);const x=await f.get();if(x.exists){await f.delete();await g.delete();await targetRef.update({followersCount:FieldValue.increment(-1)});await meRef.update({followingCount:FieldValue.increment(-1)});return ok(res,{following:false})}await f.set({uid:s.uid,createdAt:Date.now()});await g.set({uid:req.params.id,createdAt:Date.now()});await targetRef.update({followersCount:FieldValue.increment(1)});await meRef.update({followingCount:FieldValue.increment(1)});await targetRef.collection('notifications').doc().set({type:'follow',fromUserId:s.uid,fromName:(await userDoc(s.uid)).name,createdAt:Date.now(),read:false});return ok(res,{following:true})}catch(e){return fail(res,e.message,500)}});
app.get('/api/users/search',async(req,res)=>{try{const q=String(req.query.q||'').toLowerCase().trim();if(!q)return ok(res,{users:[]});const x=await firestore().collection('users').orderBy('username').startAt(q).endAt(q+'\uf8ff').limit(20).get();return ok(res,{users:x.docs.map(d=>{const u=d.data();return {uid:d.id,name:u.name,username:u.username,photoURL:u.photoURL,bio:u.bio}})})}catch(e){return fail(res,e.message,500)}});
app.get('/api/users/suggestions',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const follow=await firestore().collection('users').doc(s.uid).collection('following').get();const ids=new Set(follow.docs.map(d=>d.id));const x=await firestore().collection('users').orderBy('createdAt','desc').limit(30).get();return ok(res,{users:x.docs.map(d=>({uid:d.id,...d.data()})).filter(u=>u.uid!==s.uid&&!ids.has(u.uid)).slice(0,8).map(u=>({uid:u.uid,name:u.name,username:u.username,photoURL:u.photoURL,bio:u.bio}))})}catch(e){return fail(res,e.message,500)}});
app.get('/api/users/:id',async(req,res)=>{try{const s=currentSession(req);const u=await userDoc(req.params.id);if(!u)return fail(res,'User not found',404);let following=false;if(s&&s.uid!==req.params.id)following=(await firestore().collection('users').doc(s.uid).collection('following').doc(req.params.id).get()).exists;return ok(res,{user:{uid:u.id,name:u.name,username:u.username,bio:u.bio,photoURL:u.photoURL,coverURL:u.coverURL,followersCount:u.followersCount||0,followingCount:u.followingCount||0},following})}catch(e){return fail(res,e.message,500)}});
app.get('/api/users/:id/followers',async(req,res)=>{try{const x=await firestore().collection('users').doc(req.params.id).collection('followers').limit(200).get();const users=[];for(const d of x.docs){const u=await userDoc(d.id);if(u)users.push({uid:u.id,name:u.name,username:u.username,photoURL:u.photoURL})}return ok(res,{users})}catch(e){return fail(res,e.message,500)}});
app.get('/api/users/:id/following',async(req,res)=>{try{const x=await firestore().collection('users').doc(req.params.id).collection('following').limit(200).get();const users=[];for(const d of x.docs){const u=await userDoc(d.id);if(u)users.push({uid:u.id,name:u.name,username:u.username,photoURL:u.photoURL})}return ok(res,{users})}catch(e){return fail(res,e.message,500)}});

app.put('/api/profile',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const updates={name:String(req.body.name||'').trim().slice(0,60),bio:String(req.body.bio||'').slice(0,280),photoURL:String(req.body.photoURL||''),coverURL:String(req.body.coverURL||'')};await firestore().collection('users').doc(s.uid).update(updates);return ok(res,{user:{uid:s.uid,...updates}})}catch(e){return fail(res,e.message,500)}});

async function chatIdFor(a,b){return [a,b].sort().join('_');}
app.get('/api/chats',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const x=await firestore().collection('chats').where('members','array-contains',s.uid).limit(50).get();const chats=[];for(const d of x.docs){const c=d.data();const other=c.members.find(id=>id!==s.uid);const u=other?await userDoc(other):null;chats.push({id:d.id,other:u?{uid:u.id,name:u.name,username:u.username,photoURL:u.photoURL}:null,lastMessage:c.lastMessage||'',updatedAt:c.updatedAt||0})}chats.sort((a,b)=>b.updatedAt-a.updatedAt);return ok(res,{chats})}catch(e){return fail(res,e.message,500)}});
app.post('/api/chats/open',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const other=String(req.body.userId||'');if(!other||other===s.uid)return fail(res,'Invalid user');const id=await chatIdFor(s.uid,other);const ref=firestore().collection('chats').doc(id);if(!(await ref.get()).exists)await ref.set({members:[s.uid,other],createdAt:Date.now(),updatedAt:Date.now(),lastMessage:''});return ok(res,{chatId:id})}catch(e){return fail(res,e.message,500)}});
app.get('/api/chats/:id/messages',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const c=await firestore().collection('chats').doc(req.params.id).get();if(!c.exists||!c.data().members.includes(s.uid))return fail(res,'Forbidden',403);const x=await firestore().collection('chats').doc(req.params.id).collection('messages').orderBy('createdAt','asc').limit(200).get();return ok(res,{messages:x.docs.map(d=>({id:d.id,...d.data()}))})}catch(e){return fail(res,e.message,500)}});
app.post('/api/chats/:id/messages',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const c=await firestore().collection('chats').doc(req.params.id).get();if(!c.exists||!c.data().members.includes(s.uid))return fail(res,'Forbidden',403);const text=String(req.body.text||'').trim().slice(0,2000);const imageURL=String(req.body.imageURL||'');if(!text&&!imageURL)return fail(res,'Message is empty');const r=firestore().collection('chats').doc(req.params.id).collection('messages').doc();const m={senderId:s.uid,text,imageURL,createdAt:Date.now(),seen:false};await r.set(m);await firestore().collection('chats').doc(req.params.id).update({lastMessage:text||'📷 Photo',updatedAt:Date.now()});return ok(res,{message:{id:r.id,...m}})}catch(e){return fail(res,e.message,500)}});

app.get('/api/notifications',async(req,res)=>{try{const s=await requireUser(req,res);if(!s)return;const x=await firestore().collection('users').doc(s.uid).collection('notifications').orderBy('createdAt','desc').limit(50).get();return ok(res,{notifications:x.docs.map(d=>({id:d.id,...d.data()}))})}catch(e){return fail(res,e.message,500)}});

app.get('/api/trending',async(req,res)=>{try{const posts=await firestore().collection('posts').orderBy('createdAt','desc').limit(200).get();const map={};for(const d of posts.docs){const text=d.data().text||'';for(const t of text.match(/#[a-z0-9_]+/gi)||[])map[t.toLowerCase()]=(map[t.toLowerCase()]||0)+1}return ok(res,{hashtags:Object.entries(map).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([tag,count])=>({tag,count}))})}catch(e){return fail(res,e.message,500)}});

app.post('/api/upload', upload.single('file'), async(req,res)=>{try{if(!env('IMGBB_API_KEY'))return fail(res,'IMGBB_API_KEY is not configured',500);if(!req.file)return fail(res,'No file uploaded');const fd=new FormData();fd.append('key',env('IMGBB_API_KEY'));fd.append('image',req.file.buffer.toString('base64'));const r=await fetch('https://api.imgbb.com/1/upload',{method:'POST',body:fd});const d=await r.json();if(!r.ok||!d.success)return fail(res,d?.error?.message||'ImgBB upload failed',502);return ok(res,{url:d.data.url,display_url:d.data.display_url,thumb_url:d.data.thumb?.url||d.data.url})}catch(e){return fail(res,e.message,500)}});

app.post('/api/admin/login',async(req,res)=>{const u=String(req.body.username||'');const p=String(req.body.password||'');if(u===env('ADMIN_USERNAME')&&p===env('ADMIN_PASSWORD')){setSession(res,'admin','admin');return ok(res)}return fail(res,'Invalid admin credentials',401)});
app.post('/api/admin/logout',(req,res)=>{clearSession(res);return ok(res)});
app.get('/api/admin/data',async(req,res)=>{try{const s=await requireAdmin(req,res);if(!s)return;const dbx=firestore();const [usersSnap,postsSnap]=await Promise.all([dbx.collection('users').orderBy('createdAt','desc').limit(200).get(),dbx.collection('posts').orderBy('createdAt','desc').limit(200).get()]);const users=usersSnap.docs.map(d=>{const u=d.data();return {uid:d.id,name:u.name,email:u.email,username:u.username,photoURL:u.photoURL,role:u.role,createdAt:u.createdAt,followersCount:u.followersCount||0,followingCount:u.followingCount||0,lastSeenAt:u.lastSeenAt||0}});const posts=postsSnap.docs.map(d=>({id:d.id,...d.data()}));return ok(res,{stats:{users:users.length,posts:posts.length,online:users.filter(u=>Date.now()-u.lastSeenAt<120000).length},users,posts})}catch(e){return fail(res,e.message,500)}});
app.delete('/api/admin/posts/:id',async(req,res)=>{try{const s=await requireAdmin(req,res);if(!s)return;await firestore().collection('posts').doc(req.params.id).delete();return ok(res)}catch(e){return fail(res,e.message,500)}});
app.post('/api/admin/users/:id/role',async(req,res)=>{try{const s=await requireAdmin(req,res);if(!s)return;const role=req.body.role==='admin'?'admin':'user';await firestore().collection('users').doc(req.params.id).update({role});return ok(res)}catch(e){return fail(res,e.message,500)}});

app.use((err,req,res,next)=>{console.error(err);return fail(res,'Server error',500)});
module.exports = app;
