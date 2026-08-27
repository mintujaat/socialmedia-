# BlueWave Social Platform v3

## Included
- Login/register with signed HttpOnly session
- Home feed and Explore
- Text/photo posts
- Likes, comments, bookmarks, shares
- Profiles, edit profile, followers/following
- Search and people suggestions
- Notifications
- 1-to-1 private chat with photo messages
- Trending hashtags
- Admin dashboard and post moderation
- All images uploaded through the server to ImgBB; Firebase Storage is not required
- Responsive white + blue UI for desktop and mobile

## Vercel environment variables
FIREBASE_SERVICE_ACCOUNT_JSON = complete Firebase service account JSON
SESSION_SECRET = long random secret
IMGBB_API_KEY = ImgBB API key
ADMIN_USERNAME = optional admin username
FIREBASE_DATABASE_URL = optional

## Firebase
Create Firestore Database in the new Firebase project. The backend uses Firebase Admin SDK, so the browser never needs Firebase credentials and Firebase Storage is not used.

## Vercel
Set Root Directory to the folder containing index.html, app.js, style.css, api/, package.json and vercel.json. Leave Build Command and Output Directory at their defaults. Redeploy after environment variables are added.
