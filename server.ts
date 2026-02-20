import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dns from "dns";
import https from "https";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JWT_SECRET = process.env.JWT_SECRET || "securescan-secret-key-123";
const db = new Database("securescan.db");

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'analyst',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    url TEXT NOT NULL,
    risk_score INTEGER,
    threat_level TEXT,
    scan_result_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    rule_type TEXT,
    threshold INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

const app = express();
app.use(express.json());

// Auth Middleware
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- API Routes ---

// Auth
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)");
    const info = stmt.run(email, hash);
    res.status(201).json({ id: info.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: "User already exists" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as any;
  if (user && await bcrypt.compare(password, user.password_hash)) {
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

// Google Safe Browsing Check
async function checkGoogleSafeBrowsing(url: string) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey || apiKey === "MY_GOOGLE_SAFE_BROWSING_API_KEY") return null;

  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: "securescan", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      })
    });

    const data = await response.json() as any;
    return data.matches || [];
  } catch (e) {
    console.error("Google Safe Browsing check failed:", e);
    return null;
  }
}

// Scanning Logic - Technical Checks Only
async function performTechnicalScan(urlStr: string) {
  console.log(`Starting technical scan for: ${urlStr}`);
  let riskScore = 0;
  const indicators: string[] = [];
  let domain = "";
  let normalizedUrl = urlStr.trim();

  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = "https://" + normalizedUrl;
  }
  
  try {
    const parsedUrl = new URL(normalizedUrl);
    domain = parsedUrl.hostname;
    if (!domain) throw new Error("No hostname");
  } catch (e) {
    return { error: "Invalid URL" };
  }

  const dnsPromise = new Promise((resolve) => {
    dns.lookup(domain, (err, address) => {
      let score = 0;
      let msg = "";
      if (err) {
        score = 40;
        msg = "DNS resolution failed - Domain may not exist";
        resolve({ address: null, score, msg });
      } else {
        resolve({ address, score: 0, msg: "" });
      }
    });
  });

  const sslPromise = new Promise((resolve) => {
    if (!normalizedUrl.startsWith("https://")) {
      return resolve({ valid: false, score: 20, msg: "Using insecure HTTP protocol" });
    }

    const req = https.get(normalizedUrl, { timeout: 5000 }, (res) => {
      const cert = (res.socket as any).getPeerCertificate();
      let score = 0;
      let msg = "";
      if (!cert || Object.keys(cert).length === 0) {
        score = 30;
        msg = "Insecure or missing SSL certificate";
      }
      resolve({ valid: !!cert, score, msg });
      res.resume();
    });

    req.on('error', (err) => {
      resolve({ valid: false, score: 20, msg: `Connection error: ${err.message}` });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ valid: false, score: 15, msg: "Connection timed out" });
    });

    req.end();
  });

  const gsbPromise = checkGoogleSafeBrowsing(normalizedUrl);

  const [dnsResult, sslResult, gsbMatches]: any = await Promise.all([dnsPromise, sslPromise, gsbPromise]);

  let gsbScore = 0;
  let gsbBlacklisted = false;
  if (gsbMatches && gsbMatches.length > 0) {
    gsbBlacklisted = true;
    gsbScore = 60;
    gsbMatches.forEach((match: any) => {
      indicators.push(`Google Safe Browsing: ${match.threatType} detected`);
    });
  }

  if (dnsResult.msg) indicators.push(dnsResult.msg);
  if (sslResult.msg) indicators.push(sslResult.msg);

  riskScore = Math.max(dnsResult.score, sslResult.score, gsbScore);

  return {
    url: normalizedUrl,
    domain,
    technical_risk_score: riskScore,
    indicators,
    dns: dnsResult,
    ssl: sslResult,
    gsb: { blacklisted: gsbBlacklisted, matches: gsbMatches || [] }
  };
}

app.post("/api/scan/technical", authenticateToken, async (req: any, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL is required" });
    const result = await performTechnicalScan(url);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: "Technical scan failed" });
  }
});

app.post("/api/scan/save", authenticateToken, async (req: any, res) => {
  try {
    const { url, risk_score, threat_level, details } = req.body;
    const stmt = db.prepare("INSERT INTO scans (user_id, url, risk_score, threat_level, scan_result_json) VALUES (?, ?, ?, ?, ?)");
    const info = stmt.run(req.user.id, url, risk_score, threat_level, JSON.stringify(details));
    res.json({ id: info.lastInsertRowid });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to save scan" });
  }
});

app.get("/api/history", authenticateToken, (req: any, res) => {
  const scans = db.prepare("SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id);
  const formattedScans = scans.map((s: any) => ({
    ...s,
    details: s.scan_result_json ? JSON.parse(s.scan_result_json) : null
  }));
  res.json(formattedScans);
});

app.get("/api/dashboard-stats", authenticateToken, (req: any, res) => {
  try {
    const stats = db.prepare(`
      SELECT 
        COUNT(*) as total_scans,
        SUM(CASE WHEN threat_level = 'Malicious' THEN 1 ELSE 0 END) as malicious_count,
        SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_count
      FROM scans 
      WHERE user_id = ?
    `).get(req.user.id) as any;

    const recentScans = db.prepare(`
      SELECT date(created_at) as scan_date, COUNT(*) as count
      FROM scans 
      WHERE user_id = ? AND created_at > date('now', '-30 days')
      GROUP BY scan_date
      ORDER BY scan_date ASC
    `).all(req.user.id);

    res.json({
      total_scans: stats.total_scans || 0,
      malicious_count: stats.malicious_count || 0,
      suspicious_count: stats.suspicious_count || 0,
      recentScans: recentScans || []
    });
  } catch (error) {
    console.error("Dashboard stats error:", error);
    res.status(500).json({ error: "Failed to fetch dashboard stats" });
  }
});

app.get("/api/scan/:id", authenticateToken, (req: any, res) => {
  const scan = db.prepare("SELECT * FROM scans WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id) as any;
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  res.json({
    ...scan,
    details: JSON.parse(scan.scan_result_json)
  });
});

// --- Vite Middleware ---
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  const PORT = 3000;
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
