# NeuroShield — Real Gmail API & Google Cloud Console Setup Guide

This document provides step-by-step instructions for configuring a genuine Google Cloud Project to support NeuroShield's real Gmail API ingestion, OAuth 2.0 authentication, and Google Cloud Pub/Sub push notifications.

---

## 1. Google Cloud Project Setup

1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project or select an existing project (e.g., `neuroshield-security-soc`).
3. Note your **Project ID**.

---

## 2. Enable Required APIs & Services

Navigate to **APIs & Services > Library** and enable the following services:
- **Gmail API** (`gmail.googleapis.com`)
- **Cloud Pub/Sub API** (`pubsub.googleapis.com`) — required for real-time `watch` notifications

CLI Alternative:
```bash
gcloud services enable gmail.googleapis.com pubsub.googleapis.com --project=<YOUR_PROJECT_ID>
```

---

## 3. Configure OAuth Consent Screen

Navigate to **APIs & Services > OAuth consent screen**:
1. **User Type**:
   - Select **Internal** (if deploying for Google Workspace enterprise domains) or **External** (for testing with personal Gmail accounts).
2. **App Information**:
   - **App name**: `NeuroShield AI Phishing & Scam Defense`
   - **User support email**: Your admin/support email
   - **Developer contact information**: Your developer email
3. **Scopes**:
   - Click **Add or Remove Scopes**.
   - Add the following least-privilege scope:
     - `https://www.googleapis.com/auth/gmail.readonly` (Read resources from Gmail)
     - `email` (View primary email address)
     - `profile` (View basic profile info)
   - *Note: NeuroShield strictly enforces read-only access. Full mailbox modification or send scopes are never requested.*
4. **Test Users** (if External user type):
   - Add the Gmail addresses of test accounts intended to connect with NeuroShield.

---

## 4. Create OAuth 2.0 Client Credentials

Navigate to **APIs & Services > Credentials**:
1. Click **+ Create Credentials > OAuth client ID**.
2. **Application type**: Select **Web application**.
3. **Name**: `NeuroShield Web & Server Client`
4. **Authorized JavaScript origins**:
   - `http://localhost:3000`
   - `https://your-production-domain.com`
5. **Authorized redirect URIs**:
   - `http://localhost:3000/api/auth/google/callback`
   - `https://your-production-domain.com/api/auth/google/callback`
6. Click **Create**.
7. Securely save the generated:
   - **Client ID**
   - **Client Secret**

---

## 5. Configure Google Cloud Pub/Sub for Real-Time Push Ingestion (Optional)

To enable sub-second real-time email push notifications instead of background polling:

1. Navigate to **Pub/Sub > Topics**:
   - Click **Create Topic** (e.g. `projects/<PROJECT_ID>/topics/gmail-inbox-watch`).
2. Grant Gmail Push Permissions:
   - Select the topic > **Permissions** tab > **Add Principal**.
   - **New principal**: `gmail-api-push@system.gserviceaccount.com`
   - **Role**: `Pub/Sub Publisher` (`roles/pubsub.publisher`)
   - Click **Save**.
3. Create a Push Subscription:
   - In the topic details, click **Create Subscription**.
   - **Delivery type**: **Push**
   - **Endpoint URL**: `https://<YOUR_PUBLIC_HTTPS_DOMAIN>/api/gmail/push`
   - Set **Acknowledgment deadline**: 30 seconds.
   - Click **Create**.

---

## 6. Environment Configuration

Set the following environment variables in your server environment or `.env` file:

```env
# Google OAuth 2.0 Credentials
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/api/auth/google/callback

# Aliases also supported by GmailAuthService
GMAIL_CLIENT_ID=your-client-id.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=your-client-secret
GMAIL_REDIRECT_URI=http://localhost:3000/api/auth/google/callback

# Real-Time Push Configuration (Optional)
GMAIL_PUBSUB_TOPIC=projects/<YOUR_PROJECT_ID>/topics/gmail-inbox-watch
```

---

## 7. Security & Invariant Guarantees

- **No Secret Leakage**: The client secret is never transmitted to the browser or exposed to Chrome extensions.
- **CSRF Protection**: Every OAuth authorization URL includes a cryptographically secure, single-use `state` token verified upon return.
- **No Token Logging**: Access tokens and refresh tokens are strictly omitted from application logs.
- **Local Fallback**: When Pub/Sub push notification is not configured in local development, NeuroShield seamlessly activates the authenticated `EmailPollingController` fallback.
