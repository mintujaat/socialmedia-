# Qikly Social

Next.js + Firebase Admin/Firestore + ImgBB. Firebase Storage is intentionally not used.

## Vercel environment variables
Copy `.env.example` to your Vercel project settings:
- `NEXT_PUBLIC_FIREBASE_API_KEY` — Firebase Web API key (used for password sign-in REST call)
- `FIREBASE_PROJECT_ID`
- `FIREBASE_CLIENT_EMAIL`
- `FIREBASE_PRIVATE_KEY` — keep `\n` escaped in Vercel value
- `IMGBB_API_KEY`

Enable **Email/Password** in Firebase Authentication and create a Firestore database.

## Admin
After registering, set that user's Firestore document `role` to `admin`. Admin dashboard is `/admin`.

## Run
`npm install`
`npm run dev`

The app uses an HttpOnly Firebase session cookie and sends image files through the server to ImgBB; only the returned image URL is stored in Firestore.
