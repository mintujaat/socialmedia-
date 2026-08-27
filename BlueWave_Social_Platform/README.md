# BlueWave — HTML-first Social Platform

This build keeps the visible UI in real HTML/CSS. JavaScript is used for API calls, interactions, form submission, feed updates, image uploads, and chat behavior; it does not generate the entire site shell from an empty `<div>`.

## Deploy on Vercel
- Put these files at the project root of the Vercel project: `index.html`, `style.css`, `app.js`, `admin.html`, `admin.js`, `api/index.js`, `package.json`, `vercel.json`.
- Keep the Vercel Root Directory as the folder containing those files. Do not point it at a nested `public` folder.

## Environment variables
- `FIREBASE_SERVICE_ACCOUNT_JSON`
- `IMGBB_API_KEY`
- `SESSION_SECRET`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`

## Firestore
The backend uses Firebase Admin SDK and Firestore. Create the Firestore database in your Firebase project. No Firebase Storage is required for media uploads.

## Media
All profile/post/chat images are uploaded through `/api/media/upload` to ImgBB. Firestore stores the returned URL.
