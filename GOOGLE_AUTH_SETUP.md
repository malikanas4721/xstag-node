# Google OAuth Setup Guide

## Prerequisites
1. A Google account
2. Access to Google Cloud Console

## Steps to Set Up Google OAuth

### 1. Create a Google Cloud Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API

### 2. Create OAuth 2.0 Credentials
1. Navigate to **APIs & Services** > **Credentials**
2. Click **Create Credentials** > **OAuth client ID**
3. If prompted, configure the OAuth consent screen:
   - Choose **External** (unless you have a Google Workspace)
   - Fill in the required information
   - Add your email to test users
4. For Application type, select **Web application**
5. Add authorized redirect URIs:
   - `http://localhost:3000/api/auth/google/callback` (for development)
   - `https://yourdomain.com/api/auth/google/callback` (for production)
6. Click **Create**
7. Copy the **Client ID** and **Client Secret**

### 3. Configure Environment Variables
Create a `.env` file in the project root:

```env
PORT=3000
NODE_ENV=development

# Session Secret (generate a random string)
SESSION_SECRET=your-random-session-secret-here

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id-here
GOOGLE_CLIENT_SECRET=your-google-client-secret-here
GOOGLE_CALLBACK_URL=http://localhost:3000/api/auth/google/callback

# CORS Configuration
CORS_ORIGIN=http://localhost:3000
```

### 4. Install Dependencies
```bash
npm install
```

### 5. Start the Server
```bash
npm start
```

## Security Notes
- Never commit your `.env` file to version control
- Use strong, random session secrets in production
- Keep your Google OAuth credentials secure
- Use HTTPS in production
- Regularly rotate your OAuth credentials

## Features
- ✅ Google Gmail login
- ✅ User statistics tracking (encryption/decryption counts)
- ✅ Dashboard with activity history
- ✅ Secure session management
- ✅ Simple JSON-based user storage

## User Data Storage
User data is stored in `data/users.json`. This file is automatically created when the first user logs in.




