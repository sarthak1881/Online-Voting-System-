# CampusVote — Deployable college election portal

CampusVote is a responsive Node.js/Express web app for **college or small organizational election demos**. It includes account registration, administrator approval, candidate management, election lifecycle, one-vote-per-account checks, and results after an election closes.

> **Important:** This is a deployable educational starter, not a certified or independently audited election system. Do not use it for government, legally binding, high-stakes, or security-critical elections. The current JSON datastore is suitable only for low-traffic demos on a single persistent instance. Votes are not cryptographically anonymous and student identity is not independently verified.

## Features
- Responsive dashboard for desktop and mobile
- Voter registration and sign-in; password hashes via bcrypt
- HTTP-only session cookie and role-based API authorization
- Admin approval of voters and promotion of representatives
- Create elections, add representatives as candidates, start/close elections
- One vote per approved voter per election (application-level check)
- Results available to admins after an election is closed
- Helmet security headers, API rate limits, environment-based configuration
- Render blueprint, Dockerfile, health endpoint

## Run locally (Node.js 18+)
1. Extract the ZIP and open the folder in a terminal.
2. Copy `.env.example` to `.env`.
3. Replace `JWT_SECRET` with a long random secret and change the admin email/password.
4. Install and run:

   ```bash
   npm install
   npm start
   ```

5. Open `http://localhost:3000`.

The initial administrator is seeded from `ADMIN_EMAIL` and `ADMIN_PASSWORD` on first startup. If an admin record already exists, changing environment variables will not reset its password in production. For a fresh local demo, stop the server and remove `data/db.json` before restarting (this permanently removes demo data).

## Deploy to Render
1. Push this folder to a GitHub repository.
2. In Render, choose **New + → Blueprint** and select the repository.
3. Render reads `render.yaml`. Enter `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD` when prompted.
4. Wait for the deployment and visit the generated `onrender.com` URL.
5. Keep the persistent disk attached. The JSON database is stored under `data/db.json`; without persistent storage, data may be lost on redeploy/restart.

You can also create a Render Web Service manually with build command `npm install`, start command `npm start`, and health check `/api/health`. Set `NODE_ENV=production`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ADMIN_NAME`. Mount a persistent disk at `/opt/render/project/src/data`.

## Docker
```bash
docker build -t campusvote .
docker run --env-file .env -p 3000:3000 -v campusvote-data:/app/data campusvote
```

## First use
1. Sign in with the administrator credentials you configured.
2. Register a student account in another browser/private window.
3. As admin, approve the student or promote them to representative.
4. Create an election, add at least one approved representative, and start it.
5. Sign in as an approved voter and cast one vote.
6. Close the election to unlock the results view.

## Operational/security limitations
- JSON-file persistence is not safe for concurrent multi-instance production traffic; use a transactional database and a professionally reviewed voting protocol for real elections.
- The app does not provide email verification, password reset, institutional identity verification, MFA, independent audit logging, or cryptographic ballot secrecy.
- The vote receipt and vote record are separated in storage but are not proof of cryptographic anonymity.
- Configure backups, monitor logs, rotate secrets, and perform an independent security review before any real-world deployment.
