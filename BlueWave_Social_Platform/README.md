# BlueWave Social Platform

A Vercel-ready social network using Firebase Firestore for data and ImgBB for all images.

## Vercel environment variables

- `FIREBASE_SERVICE_ACCOUNT_JSON` — full Firebase service-account JSON
- `FIREBASE_DATABASE_URL` — optional; only needed if you also use Realtime Database
- `IMGBB_API_KEY` — ImgBB API key
- `SESSION_SECRET` — long random secret for login cookies
- `ADMIN_USERNAME` — optional username allowed to view `/api/admin/stats`

## Firebase

Create Firestore in the new Firebase project. The app uses the Firebase Admin SDK, so Firestore rules are bypassed by the server; still keep normal client rules locked down because this app does not use the client SDK for data access.

Collections created automatically: `users`, `posts`, `postLikes`, `comments`, `bookmarks`, `follows`, `notifications`, `conversations` (with `messages` subcollections).

## Images

Profile photos, post photos and chat photos all go through `/api/media/upload` to ImgBB. Only the resulting URL is stored in Firestore. Firebase Storage is not used.

## Deploy

Set the Vercel Root Directory to `BlueWave_Social_Platform` if this folder is nested inside a larger GitHub repository. No build command is required. Redeploy after setting environment variables.
