# duemate-backend

Smart WhatsApp assignment and quiz reminder bot backend built with Flask.

## Required Environment Variables

Set these in Render (and locally in `.env`):

- `FLASK_SECRET_KEY`
- `MONGODB_URI`
- `META_BEARER_TOKEN`
- `META_PHONE_NUMBER_ID`
- `META_BUSINESS_ACCOUNT_ID`
- `META_VERIFY_TOKEN`
- `META_APP_SECRET`
- `PORT` (Render sets this automatically)

Backward-compatible aliases are also supported in code:

- `MONGO_URI` (alias of `MONGODB_URI`)
- `META_ACCESS_TOKEN` (alias of `META_BEARER_TOKEN`)
- `WEBHOOK_VERIFY_TOKEN` (alias of `META_VERIFY_TOKEN`)
- `SECRET_KEY` (alias of `FLASK_SECRET_KEY`)

## Render Setup

1. Open Render service for `duemate-backend`.
2. Go to Environment and add the required variables above.
3. Save changes and trigger a redeploy.

## Keep-Alive (cron-job.org)

To reduce free-tier sleep impact, create a cron job:

- URL: `https://duemate-backend-31qm.onrender.com/health`
- Method: `GET`
- Schedule: every 10 minutes

## Connectivity Verification

After deploy, verify health endpoint:

- `GET /health` should return `status: ok`
- `mongo_configured: true`
- `meta_configured: true`
- `mongo_connected: true` (after latest code is deployed)
