export async function uploadToImgBB(file: File) {
  const key = process.env.IMGBB_API_KEY;
  if (!key) throw new Error('IMGBB_API_KEY is not configured');
  const bytes = Buffer.from(await file.arrayBuffer());
  const base64 = bytes.toString('base64');
  const form = new URLSearchParams(); form.set('key', key); form.set('image', base64);
  const r = await fetch('https://api.imgbb.com/1/upload', { method:'POST', body: form });
  const data = await r.json();
  if (!r.ok || !data.success) throw new Error(data?.error?.message || 'ImgBB upload failed');
  return { url:data.data.url, displayUrl:data.data.display_url, deleteUrl:data.data.delete_url, thumb:data.data.thumb?.url };
}
