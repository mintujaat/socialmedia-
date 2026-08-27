# BlueWave Social Platform

HTML/CSS/JS-first social platform for Vercel + Firebase Firestore + ImgBB.

## Features
- Email + username + password registration/login
- Home feed and Explore
- Posts with text/photos
- Likes, comments, bookmarks, shares
- Follow / unfollow, followers / following
- User search and suggestions
- Profiles and profile editing
- Private 1-to-1 chat and chat images
- Notifications
- Admin dashboard for users and post moderation
- ImgBB for profile/cover/post/chat images; Firebase Storage is not required

## Vercel
Set Root Directory to the folder containing `index.html` and `api/`.
No build command is required.

### Environment variables
- FIREBASE_SERVICE_ACCOUNT_JSON
- IMGBB_API_KEY
- SESSION_SECRET
- ADMIN_USERNAME
- ADMIN_PASSWORD

Optional legacy Firebase variables are supported by the API fallback, but the recommended setup is `FIREBASE_SERVICE_ACCOUNT_JSON`.

## Firebase
Enable Firestore. Deploy the included `firestore.rules` if Firestore is used only through the backend Admin SDK.
