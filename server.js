require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DB_DIR, "db.json");

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error("ERROR: Set JWT_SECRET in .env to a random string at least 32 characters long.");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false }));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const emailOf = (v) => String(v || "").trim().toLowerCase();
const clean = (v, max = 200) => String(v || "").trim().slice(0, max);
const publicUser = (u) => ({
  id: u.id, name: u.name, email: u.email, admissionNo: u.admissionNo || "",
  role: u.role, approved: Boolean(u.approved), createdAt: u.createdAt
});

function ensureDb() {
  fs.mkdirSync(DB_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], elections: [], candidates: [], votes: [], receipts: [] }, null, 2));
  }
}
function readDb() {
  ensureDb();
  try {
    const d = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    for (const k of ["users", "elections", "candidates", "votes", "receipts"]) if (!Array.isArray(d[k])) d[k] = [];
    return d;
  } catch (e) {
    throw new Error("The data/db.json file is invalid JSON. Stop the server and restore/fix that file.");
  }
}
function writeDb(db) {
  ensureDb();
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
function setSession(res, user) {
  const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: "8h" });
  res.cookie("campus_token", token, {
    httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000, path: "/"
  });
}
function auth(req, res, next) {
  try {
    const token = req.cookies.campus_token;
    if (!token) return res.status(401).json({ error: "Please sign in first." });
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const db = readDb();
    const user = db.users.find(u => u.id === payload.sub);
    if (!user) return res.status(401).json({ error: "Account not found." });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Your session expired. Please sign in again." });
  }
}
function allow(...roles) {
  return (req, res, next) => req.user && roles.includes(req.user.role)
    ? next() : res.status(403).json({ error: "You do not have permission to do that." });
}
function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

async function seedAdmin() {
  const db = readDb();
  const email = emailOf(process.env.ADMIN_EMAIL);
  const password = String(process.env.ADMIN_PASSWORD || "");
  if (!email || password.length < 12) {
    console.warn("Admin not seeded: set ADMIN_EMAIL and ADMIN_PASSWORD (12+ characters) in .env.");
    return;
  }
  const existingAdmin = db.users.find(u => u.email === email);

  if (!existingAdmin) {
    db.users.push({
      id: id(), name: clean(process.env.ADMIN_NAME || "Election Administrator", 100),
      email, admissionNo: "", passwordHash: await bcrypt.hash(password, 12),
      role: "admin", approved: true, createdAt: now()
    });
    writeDb(db);
    console.log("Initial admin account created:", email);
    return;
  }

  // Local demo recovery: the configured ADMIN_EMAIL is the admin identity.
  // In development, repair a stale demo account or reset its password to the
  // value in .env. Never do this automatically in production.
  if (process.env.NODE_ENV !== "production") {
    const passwordMatches = await bcrypt.compare(password, existingAdmin.passwordHash || "");
    if (existingAdmin.role !== "admin" || !passwordMatches || !existingAdmin.approved) {
      existingAdmin.role = "admin";
      existingAdmin.approved = true;
      existingAdmin.name = clean(process.env.ADMIN_NAME || "Election Administrator", 100);
      existingAdmin.admissionNo = "";
      existingAdmin.passwordHash = await bcrypt.hash(password, 12);
      writeDb(db);
      console.log("Development admin account repaired from .env:", email);
    }
  }
}

app.get("/api/health", (req, res) => res.json({ ok: true, service: "CampusVote" }));

app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const name = clean(req.body.name, 100);
  const admissionNo = clean(req.body.admissionNo, 30).toUpperCase();
  const email = emailOf(req.body.email);
  const password = String(req.body.password || "");
  if (name.length < 2 || !/^[A-Z0-9/-]{3,30}$/.test(admissionNo) ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) {
    return res.status(400).json({ error: "Enter your name, valid admission number, email, and password (at least 8 characters)." });
  }
  const db = readDb();
  // Explain exactly which unique field conflicts, instead of a vague duplicate error.
  if (db.users.some(u => u.email === email)) {
    return res.status(409).json({ error: "This email address is already registered. Sign in with the original account or use a different email." });
  }
  if (db.users.some(u => u.admissionNo && u.admissionNo === admissionNo)) {
    return res.status(409).json({ error: "This admission number is already registered with an account. Use the email originally registered, or reset the demo database if you want to start over." });
  }
  const user = {
    id: id(), name, admissionNo, email, passwordHash: await bcrypt.hash(password, 12),
    role: "voter", approved: false, createdAt: now()
  };
  db.users.push(user);
  writeDb(db);
  // Sign in immediately after successful registration so the user does not have
  // to retype the password (and risk mistyping it on the sign-in form).
  setSession(res, user);
  res.status(201).json({
    message: "Account created and signed in. Administrator approval is required before voting.",
    user: publicUser(user)
  });
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const email = emailOf(req.body.email);
  const password = String(req.body.password || "");
  const db = readDb();
  const user = db.users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Invalid email or password." });
  }
  setSession(res, user);
  res.json({ user: publicUser(user) });
}));
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("campus_token", { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production", path: "/" });
  res.json({ message: "Signed out." });
});
app.get("/api/auth/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.get("/api/elections", (req, res) => {
  const db = readDb();
  res.json({ elections: db.elections.slice().sort((a,b) => b.createdAt.localeCompare(a.createdAt)) });
});
app.get("/api/elections/:electionId/candidates", (req, res) => {
  const db = readDb();
  const election = db.elections.find(e => e.id === req.params.electionId);
  if (!election) return res.status(404).json({ error: "Election not found." });
  res.json({ candidates: db.candidates.filter(c => c.electionId === election.id).map(c => {
    const user = db.users.find(u => u.id === c.userId);
    return { id: c.id, name: user ? user.name : "Unknown candidate", position: c.position, department: c.department, manifesto: c.manifesto };
  }) });
});

app.post("/api/admin/elections", auth, allow("admin"), (req, res) => {
  const title = clean(req.body.title, 120);
  const description = clean(req.body.description, 500);
  if (title.length < 3) return res.status(400).json({ error: "Election title must be at least 3 characters." });
  const db = readDb();
  const election = { id: id(), title, description, status: "draft", createdAt: now(), startsAt: null, endsAt: null };
  db.elections.push(election); writeDb(db);
  res.status(201).json({ election });
});
app.post("/api/admin/elections/:id/start", auth, allow("admin"), (req, res) => {
  const db = readDb();
  const election = db.elections.find(e => e.id === req.params.id);
  if (!election) return res.status(404).json({ error: "Election not found." });
  if (election.status !== "draft") return res.status(400).json({ error: "Only draft elections can be started." });
  if (!db.candidates.some(c => c.electionId === election.id)) return res.status(400).json({ error: "Add at least one candidate before starting." });
  election.status = "active"; election.startsAt = now(); writeDb(db);
  res.json({ election });
});
app.post("/api/admin/elections/:id/close", auth, allow("admin"), (req, res) => {
  const db = readDb();
  const election = db.elections.find(e => e.id === req.params.id);
  if (!election || election.status !== "active") return res.status(404).json({ error: "Active election not found." });
  election.status = "closed"; election.endsAt = now(); writeDb(db);
  res.json({ election });
});
app.get("/api/admin/users/pending", auth, allow("admin"), (req, res) => {
  const db = readDb();
  res.json({ users: db.users.filter(u => u.role === "voter" && !u.approved).map(publicUser) });
});
app.get("/api/admin/users", auth, allow("admin"), (req, res) => {
  const db = readDb();
  res.json({ users: db.users.filter(u => u.role !== "admin").map(publicUser) });
});
app.post("/api/admin/users/:id/approve", auth, allow("admin"), (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.params.id && u.role === "voter");
  if (!user) return res.status(404).json({ error: "Voter account not found." });
  user.approved = true; writeDb(db); res.json({ user: publicUser(user) });
});
app.post("/api/admin/users/:id/representative", auth, allow("admin"), (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.params.id && u.role !== "admin");
  if (!user) return res.status(404).json({ error: "Student account not found." });
  user.role = "representative"; user.approved = true; writeDb(db);
  res.json({ user: publicUser(user) });
});
app.post("/api/admin/users/:id/voter", auth, allow("admin"), (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.params.id && u.role !== "admin");
  if (!user) return res.status(404).json({ error: "Student account not found." });
  user.role = "voter"; user.approved = true; writeDb(db);
  res.json({ user: publicUser(user) });
});
app.post("/api/admin/elections/:id/candidates", auth, allow("admin"), (req, res) => {
  const db = readDb();
  const election = db.elections.find(e => e.id === req.params.id);
  if (!election) return res.status(404).json({ error: "Election not found." });
  if (election.status !== "draft") return res.status(400).json({ error: "Candidates can only be added before voting starts." });

  // Accept multiple representative IDs (and the old single userId field for compatibility).
  const userIds = [...new Set((Array.isArray(req.body.userIds) ? req.body.userIds : [req.body.userId]).filter(Boolean))];
  if (!userIds.length) return res.status(400).json({ error: "Select at least one representative." });
  const users = userIds.map(userId => db.users.find(u => u.id === userId && u.role === "representative" && u.approved));
  if (users.some(u => !u)) return res.status(400).json({ error: "One or more selected accounts are not approved representatives." });
  const duplicates = users.filter(user => db.candidates.some(c => c.electionId === election.id && c.userId === user.id));
  if (duplicates.length) return res.status(409).json({ error: `Already added to this election: ${duplicates.map(u => u.name).join(", ")}. Remove duplicates from your selection and try again.` });

  const added = users.map(user => ({
    id: id(), electionId: election.id, userId: user.id,
    position: clean(req.body.position || "Student Representative", 100),
    department: clean(req.body.department, 100), manifesto: clean(req.body.manifesto, 1000), createdAt: now(),
    name: user.name
  }));
  db.candidates.push(...added.map(({ name, ...candidate }) => candidate));
  writeDb(db);
  res.status(201).json({ added });
});
app.get("/api/admin/representatives", auth, allow("admin"), (req, res) => {
  const db = readDb();
  res.json({ representatives: db.users.filter(u => u.role === "representative" && u.approved).map(publicUser) });
});

app.post("/api/representative/apply", auth, allow("representative"), (req, res) => {
  const db = readDb();
  const election = db.elections.find(e => e.id === req.body.electionId && e.status === "draft");
  if (!election) return res.status(400).json({ error: "Applications are only allowed before the election starts." });
  if (db.candidates.some(c => c.electionId === election.id && c.userId === req.user.id)) {
    return res.status(409).json({ error: "You have already applied to this election." });
  }
  const candidate = {
    id: id(), electionId: election.id, userId: req.user.id,
    position: clean(req.body.position || "Student Representative", 100),
    department: clean(req.body.department, 100), manifesto: clean(req.body.manifesto, 1000), createdAt: now()
  };
  db.candidates.push(candidate); writeDb(db);
  res.status(201).json({ message: "Your candidacy has been submitted." });
});
app.get("/api/representative/mine", auth, allow("representative"), (req, res) => {
  const db = readDb();
  res.json({ candidates: db.candidates.filter(c => c.userId === req.user.id).map(c => ({
    ...c, election: db.elections.find(e => e.id === c.electionId)
  })) });
});

app.post("/api/vote/submit", auth, allow("voter"), (req, res) => {
  if (!req.user.approved) return res.status(403).json({ error: "Your account is awaiting admin approval." });
  const db = readDb();
  const election = db.elections.find(e => e.id === req.body.electionId && e.status === "active");
  if (!election) return res.status(400).json({ error: "This election is not active." });
  if (db.receipts.some(r => r.electionId === election.id && r.userId === req.user.id)) {
    return res.status(409).json({ error: "You have already voted in this election." });
  }
  const candidate = db.candidates.find(c => c.id === req.body.candidateId && c.electionId === election.id);
  if (!candidate) return res.status(400).json({ error: "Choose a valid candidate for this election." });
  const receipt = crypto.randomBytes(32).toString("hex");
  // Demo-only JSON storage: receipt and vote are separate records, but this is not a certified anonymous voting protocol.
  db.receipts.push({ id: id(), electionId: election.id, userId: req.user.id, receiptHash: crypto.createHash("sha256").update(receipt).digest("hex"), createdAt: now() });
  db.votes.push({ id: id(), electionId: election.id, candidateId: candidate.id, receiptHash: crypto.createHash("sha256").update(receipt).digest("hex"), createdAt: now() });
  writeDb(db);
  res.json({ message: "Your vote has been recorded." });
});
app.get("/api/vote/status/:electionId", auth, (req, res) => {
  const db = readDb();
  res.json({ voted: db.receipts.some(r => r.electionId === req.params.electionId && r.userId === req.user.id) });
});
app.get("/api/admin/elections/:id/results", auth, allow("admin"), (req, res) => {
  const db = readDb();
  const election = db.elections.find(e => e.id === req.params.id);
  if (!election) return res.status(404).json({ error: "Election not found." });
  if (election.status !== "closed") return res.status(400).json({ error: "Results are available only after the election is closed." });
  const candidates = db.candidates.filter(c => c.electionId === election.id).map(c => {
    const user = db.users.find(u => u.id === c.userId);
    return { candidateId: c.id, name: user ? user.name : "Unknown", position: c.position, department: c.department,
      votes: db.votes.filter(v => v.electionId === election.id && v.candidateId === c.id).length };
  }).sort((a,b) => b.votes - a.votes);
  res.json({ election, results: candidates, totalVotes: db.votes.filter(v => v.electionId === election.id).length });
});

app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.use("/api", (req, res) => res.status(404).json({ error: "API endpoint not found." }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Unexpected server error. Check the terminal for details." });
});

ensureDb();
seedAdmin().then(() => {
  app.listen(PORT, () => console.log(`CampusVote running at http://localhost:${PORT}`));
}).catch(err => {
  console.error("Startup failed:", err);
  process.exit(1);
});
