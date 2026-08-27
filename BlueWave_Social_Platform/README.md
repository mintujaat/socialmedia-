# BlueWave Social Platform

A Vercel-ready social web app using:
- Express + Firebase Admin / Firestore
- ImgBB for profile, post and chat images
- Signed HttpOnly session cookie auth
- Single-page user experience in `index.html`
- Separate `admin.html` control panel

## Vercel environment variables
- `FIREBASE_SERVICE_ACCOUNT_JSON` (full service-account JSON)
- `IMGBB_API_KEY`
- `SESSION_SECRET` (long random string)
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`

## Deploy
Set the Vercel Root Directory to the folder containing `index.html`, `api/`, `package.json`, and `vercel.json`.
No Firebase Storage is required.
