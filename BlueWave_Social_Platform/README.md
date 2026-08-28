# BlueWave Social Platform

HTML-first social platform for Vercel + Firebase Firestore + ImgBB.

## Vercel
Root directory should be the folder containing `index.html`, `api/`, `package.json`, and `vercel.json`.

Environment variables:
- FIREBASE_SERVICE_ACCOUNT_JSON
- FIREBASE_DATABASE_URL (optional for current Firestore-first app)
- IMGBB_API_KEY
- SESSION_SECRET
- ADMIN_USERNAME
- ADMIN_PASSWORD

Images are uploaded through `/api/upload` and only the returned ImgBB URL is stored in Firestore.
