# Google Cloud / Gmail OAuth Setup Guide

This guide walks you through setting up Google OAuth 2.0 credentials for PhishGuard's Gmail integration.

**PhishGuard requests READ-ONLY access to your Gmail inbox.** It never sends, deletes, modifies, or replies to emails.

---

## Step 1: Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Sign in with your Google account
3. Click **Select a project** at the top of the page
4. Click **New Project**
5. Enter a project name (e.g., "PhishGuard")
6. Click **Create**
7. Wait for the project to be created, then select it

---

## Step 2: Enable the Gmail API

1. In the Google Cloud Console, go to **APIs & Services** > **Library**
2. Search for "Gmail API"
3. Click on **Gmail API**
4. Click **Enable**
5. Wait for the API to be enabled

---

## Step 3: Configure the OAuth Consent Screen

1. Go to **APIs & Services** > **OAuth consent screen**
2. Select **External** user type (unless you have a Google Workspace org)
3. Click **Create**
4. Fill in the required fields:
   - **App name**: PhishGuard (or any name you prefer)
   - **User support email**: Your email address
   - **Developer contact information**: Your email address
5. Click **Save and Continue**
6. On the **Scopes** page, click **Add or Remove Scopes**
7. Search for and add:
   - `https://www.googleapis.com/auth/gmail.readonly`
8. Click **Update**, then **Save and Continue**
9. On the **Test users** page:
   - Click **Add Users**
   - Enter the Gmail address you want to connect
   - Click **Add**, then **Save and Continue**
10. Click **Back to Dashboard**

**Note:** While in "Testing" mode, only users listed as test users can authorize the app. To allow any user, you would need to complete Google's verification process.

---

## Step 4: Create OAuth 2.0 Credentials

1. Go to **APIs & Services** > **Credentials**
2. Click **+ Create Credentials** > **OAuth client ID**
3. Select **Web application** as the application type
4. Enter a name (e.g., "PhishGuard Web Client")
5. Under **Authorized redirect URIs**, click **+ Add URI**
6. Enter: `http://localhost:8000/auth/google/callback`
7. Click **Create**
8. Copy the **Client ID** and **Client Secret**

---

## Step 5: Configure PhishGuard

1. Open `backend/.env` in your text editor
2. Fill in the credentials:

```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback
```

3. Save the file

**Never commit `.env` to Git.** It is already in `.gitignore`.

---

## Step 6: Test the Connection

1. Start the backend:
   ```bash
   cd backend
   uvicorn app.main:app --reload --port 8000
   ```

2. Start the frontend:
   ```bash
   cd frontend
   npm run dev
   ```

3. Open PhishGuard at `http://localhost:5173`
4. Go to **Settings**
5. Click **Connect Gmail**
6. Sign in with the test user Gmail account
7. Grant read-only access
8. You should be redirected back to PhishGuard with "Gmail Connected"

---

## Troubleshooting

### "OAuth not configured" error

- Ensure `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set in `backend/.env`
- Make sure there are no extra spaces or quotes around the values

### Redirect URI mismatch

- The redirect URI in Google Cloud Console must exactly match: `http://localhost:8000/auth/google/callback`
- Check for trailing slashes or different ports

### "Access blocked" error

- Your Gmail account must be listed as a **test user** in the OAuth consent screen
- The app must be in **Testing** mode (not "Published")

### Token expired / Gmail sync fails

- PhishGuard automatically refreshes expired tokens
- If refresh fails, disconnect and reconnect your Gmail account in Settings

### "Gmail API has not been used in project" error

- Go to **APIs & Services** > **Library** and enable the Gmail API

---

## Security Notes

- PhishGuard uses **read-only** Gmail access (`gmail.readonly` scope)
- OAuth tokens are stored **server-side** in the SQLite database
- Tokens are **never** exposed to the React frontend
- PhishGuard never sends, deletes, modifies, or replies to emails
- URLs in emails are analyzed statically — they are never visited
- Attachments are never opened or executed

---

## Production Considerations

For production deployment:

1. **HTTPS**: Google requires HTTPS for OAuth redirect URIs in production
2. **Token storage**: Replace SQLite with a production database (PostgreSQL)
3. **Token encryption**: Encrypt stored tokens at rest
4. **App verification**: Complete Google's app verification for public use
5. **Rate limiting**: Implement rate limiting for Gmail API calls
6. **Webhook**: Consider using Gmail push notifications (Pub/Sub) instead of polling for real-time analysis
