import express, { Request, Response, NextFunction } from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import fs from "fs";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();

// --- Constants & Config ---
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-key-change-in-prod";
const DB_PATH = path.join(process.cwd(), "rural_health.db");

// --- Database Setup ---
const db = new Database(DB_PATH);

// Initialize Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('patient', 'doctor', 'worker', 'admin')) NOT NULL,
    age INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    doctor_id INTEGER,
    date DATETIME NOT NULL,
    status TEXT CHECK(status IN ('pending', 'confirmed', 'completed', 'cancelled')) DEFAULT 'pending',
    type TEXT CHECK(type IN ('in-person', 'teleconsultation')) NOT NULL,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(patient_id) REFERENCES users(id),
    FOREIGN KEY(doctor_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS health_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    type TEXT NOT NULL, -- bp, sugar, heart_rate, oxygen, weight, temp
    value TEXT NOT NULL,
    unit TEXT NOT NULL,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(patient_id) REFERENCES users(id)
  );
  
  CREATE TABLE IF NOT EXISTS medical_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    doctor_id INTEGER NOT NULL,
    diagnosis TEXT,
    prescription TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(patient_id) REFERENCES users(id),
    FOREIGN KEY(doctor_id) REFERENCES users(id)
  );
`);

// Migration: Add age column if it doesn't exist
try {
  db.prepare("ALTER TABLE users ADD COLUMN age INTEGER").run();
} catch (err: any) {
  // Column likely exists
}

// Seed Admin/Doctor if not exists
const checkUser = db.prepare("SELECT count(*) as count FROM users").get() as { count: number };
if (checkUser.count === 0) {
  const hash = bcrypt.hashSync("password123", 10);
  const insert = db.prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
  insert.run("Dr. Sarah Smith", "doctor@example.com", hash, "doctor");
  insert.run("John Doe", "patient@example.com", hash, "patient");
  insert.run("Jane Health", "worker@example.com", hash, "worker");
  insert.run("Admin User", "admin@example.com", hash, "admin");
  console.log("Database seeded with default users.");
}

// Ensure additional doctors exist
const additionalDoctors = [
  { name: "Dr. Emily Chen", email: "emily.chen@example.com", role: "doctor" },
  { name: "Dr. Michael Ross", email: "michael.ross@example.com", role: "doctor" },
  { name: "Dr. Linda Johnson", email: "linda.johnson@example.com", role: "doctor" },
  { name: "Dr. Robert Wilson", email: "robert.wilson@example.com", role: "doctor" },
  { name: "Dr. Karen Davis", email: "karen.davis@example.com", role: "doctor" },
  { name: "Dr. James Miller", email: "james.miller@example.com", role: "doctor" },
  { name: "Dr. Patricia Taylor", email: "patricia.taylor@example.com", role: "doctor" }
];

const insertDoctor = db.prepare("INSERT OR IGNORE INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
const hash = bcrypt.hashSync("password123", 10);

// Force update default doctor password to ensure access
db.prepare("UPDATE users SET password = ? WHERE email = ?").run(hash, "doctor@example.com");

additionalDoctors.forEach(doc => {
  insertDoctor.run(doc.name, doc.email, hash, doc.role);
});

// --- Seed Dummy Data (Patients, Appointments, Records) ---
const dummyPatients = [
  { name: "Alice Walker", email: "alice@example.com", age: 34, role: "patient" },
  { name: "Bob Brown", email: "bob@example.com", age: 56, role: "patient" },
  { name: "Charlie Davis", email: "charlie@example.com", age: 22, role: "patient" },
  { name: "Diana Evans", email: "diana@example.com", age: 45, role: "patient" },
  { name: "Evan Foster", email: "evan@example.com", age: 67, role: "patient" },
  { name: "Fiona Green", email: "fiona@example.com", age: 29, role: "patient" },
  { name: "George Harris", email: "george@example.com", age: 38, role: "patient" },
  { name: "Hannah White", email: "hannah@example.com", age: 51, role: "patient" }
];

const insertPatient = db.prepare("INSERT OR IGNORE INTO users (name, email, password, role, age) VALUES (?, ?, ?, ?, ?)");
dummyPatients.forEach(p => {
  insertPatient.run(p.name, p.email, hash, p.role, p.age);
});

// Seed Dummy Appointments for Dr. Sarah Smith (doctor@example.com)
try {
  const doctor = db.prepare("SELECT id FROM users WHERE email = 'doctor@example.com'").get() as { id: number };
  const patients = db.prepare("SELECT id FROM users WHERE role = 'patient' AND email != 'patient@example.com'").all() as { id: number }[];

  if (doctor && patients.length > 0) {
    const checkAppts = db.prepare("SELECT count(*) as count FROM appointments WHERE doctor_id = ?").get(doctor.id) as { count: number };
    
    if (checkAppts.count < 5) {
      const insertAppt = db.prepare("INSERT INTO appointments (patient_id, doctor_id, date, status, type, notes) VALUES (?, ?, ?, ?, ?, ?)");
      
      // Upcoming
      if (patients[0]) insertAppt.run(patients[0].id, doctor.id, new Date(Date.now() + 86400000).toISOString(), 'confirmed', 'in-person', 'Regular checkup');
      if (patients[1]) insertAppt.run(patients[1].id, doctor.id, new Date(Date.now() + 172800000).toISOString(), 'pending', 'teleconsultation', 'Follow up on medication');
      if (patients[2]) insertAppt.run(patients[2].id, doctor.id, new Date(Date.now() + 259200000).toISOString(), 'confirmed', 'in-person', 'Back pain consultation');
      
      // Past
      if (patients[3]) insertAppt.run(patients[3].id, doctor.id, new Date(Date.now() - 86400000).toISOString(), 'completed', 'in-person', 'Annual physical');
      if (patients[4]) insertAppt.run(patients[4].id, doctor.id, new Date(Date.now() - 172800000).toISOString(), 'completed', 'teleconsultation', 'Skin rash review');
    }

    // Seed Dummy Medical Records
    const checkRecords = db.prepare("SELECT count(*) as count FROM medical_records WHERE doctor_id = ?").get(doctor.id) as { count: number };
    if (checkRecords.count === 0) {
       const insertRecord = db.prepare("INSERT INTO medical_records (patient_id, doctor_id, diagnosis, prescription, created_at) VALUES (?, ?, ?, ?, ?)");
       
       if (patients[0]) insertRecord.run(patients[0].id, doctor.id, "Hypertension", "Lisinopril 10mg daily", new Date(Date.now() - 100000000).toISOString());
       if (patients[1]) insertRecord.run(patients[1].id, doctor.id, "Type 2 Diabetes", "Metformin 500mg twice daily", new Date(Date.now() - 200000000).toISOString());
       if (patients[3]) insertRecord.run(patients[3].id, doctor.id, "Seasonal Allergies", "Cetirizine 10mg as needed", new Date(Date.now() - 50000000).toISOString());
       if (patients[4]) insertRecord.run(patients[4].id, doctor.id, "Eczema", "Hydrocortisone cream 1%", new Date(Date.now() - 150000000).toISOString());
    }
  }
} catch (err) {
  console.error("Error seeding dummy data:", err);
}

// --- Helper: Heuristic Analysis ---
function analyzeMetricsRuleBased(metrics: any[]): { risk: string, analysis: string } {
  if (!metrics || metrics.length === 0) {
    return { risk: "Low", analysis: "No metrics available for analysis. Please record vitals." };
  }

  let riskScore = 0;
  let observations: string[] = [];

  // Get latest values for each type
  const latest: Record<string, any> = {};
  metrics.forEach(m => {
    // Assuming metrics are ordered or we just take the last one seen
    latest[m.type] = m;
  });

  // Blood Pressure Check
  if (latest['bp']) {
    const [sys, dia] = latest['bp'].value.split('/').map(Number);
    if (sys > 140 || dia > 90) {
      riskScore += 2;
      observations.push(`Blood pressure is high (${latest['bp'].value} mmHg).`);
    } else if (sys > 120 || dia > 80) {
      riskScore += 1;
      observations.push(`Blood pressure is slightly elevated (${latest['bp'].value} mmHg).`);
    } else {
      observations.push(`Blood pressure is normal.`);
    }
  }

  // Heart Rate Check
  if (latest['heart_rate']) {
    const hr = Number(latest['heart_rate'].value);
    if (hr > 100 || hr < 60) {
      riskScore += 1;
      observations.push(`Heart rate is abnormal (${hr} bpm).`);
    } else {
      observations.push(`Heart rate is normal.`);
    }
  }

  // Blood Sugar Check
  if (latest['sugar']) {
    const sugar = Number(latest['sugar'].value);
    if (sugar > 140) {
      riskScore += 2;
      observations.push(`Blood sugar is high (${sugar} mg/dL).`);
    } else {
      observations.push(`Blood sugar is within normal range.`);
    }
  }

  // Oxygen Check
  if (latest['oxygen']) {
    const spo2 = Number(latest['oxygen'].value);
    if (spo2 < 95) {
      riskScore += 2;
      observations.push(`Oxygen saturation is low (${spo2}%).`);
    } else {
      observations.push(`Oxygen levels are good.`);
    }
  }

  // Determine Risk Level
  let riskLevel = "Low";
  if (riskScore >= 3) riskLevel = "High";
  else if (riskScore >= 1) riskLevel = "Medium";

  // Construct Analysis Text
  let analysisText = `Based on your recent metrics: ${observations.join(" ")} `;
  if (riskLevel === "High") {
    analysisText += "Immediate medical attention or consultation is recommended.";
  } else if (riskLevel === "Medium") {
    analysisText += "Regular monitoring and lifestyle adjustments are advised.";
  } else {
    analysisText += "Your vitals appear healthy. Keep up the good work!";
  }

  return { risk: riskLevel, analysis: analysisText };
}

// --- Express App Setup ---
async function startServer() {
  const app = express();
  app.use(express.json());

  // --- Middleware ---
  const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.sendStatus(403);
      (req as any).user = user;
      next();
    });
  };

  // --- API Routes ---

  // Auth
  app.post("/api/auth/login", (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as any;
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  });

  app.post("/api/auth/register", (req, res) => {
    const { name, email, password, role } = req.body;
    try {
      const hash = bcrypt.hashSync(password, 10);
      const result = db.prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)").run(name, email, hash, role || 'patient');
      res.json({ id: result.lastInsertRowid, success: true });
    } catch (err: any) {
      res.status(400).json({ error: "Email likely already exists" });
    }
  });

  // Appointments
  app.get("/api/appointments", authenticateToken, (req: Request, res: Response) => {
    const user = (req as any).user;
    let stmt;
    if (user.role === 'patient') {
      stmt = db.prepare("SELECT a.*, u.name as doctor_name FROM appointments a LEFT JOIN users u ON a.doctor_id = u.id WHERE a.patient_id = ? ORDER BY date DESC");
      res.json(stmt.all(user.id));
    } else if (user.role === 'doctor') {
      stmt = db.prepare("SELECT a.*, u.name as patient_name FROM appointments a JOIN users u ON a.patient_id = u.id WHERE a.doctor_id = ? ORDER BY date DESC");
      res.json(stmt.all(user.id));
    } else {
      stmt = db.prepare("SELECT a.*, p.name as patient_name, d.name as doctor_name FROM appointments a JOIN users p ON a.patient_id = p.id LEFT JOIN users d ON a.doctor_id = d.id ORDER BY date DESC");
      res.json(stmt.all());
    }
  });

  app.post("/api/appointments", authenticateToken, (req: Request, res: Response) => {
    const { doctor_id, date, type, notes } = req.body;
    const user = (req as any).user;
    try {
      const result = db.prepare("INSERT INTO appointments (patient_id, doctor_id, date, type, notes) VALUES (?, ?, ?, ?, ?)").run(user.id, doctor_id, date, type, notes);
      res.json({ id: result.lastInsertRowid, success: true });
    } catch (err: any) {
      console.error("Booking Error:", err);
      res.status(500).json({ error: "Failed to book appointment: " + err.message });
    }
  });

  app.patch("/api/appointments/:id", authenticateToken, (req: Request, res: Response) => {
    const { status } = req.body;
    const { id } = req.params;
    db.prepare("UPDATE appointments SET status = ? WHERE id = ?").run(status, id);
    res.json({ success: true });
  });

  // Health Metrics
  app.get("/api/metrics", authenticateToken, (req: Request, res: Response) => {
    const user = (req as any).user;
    const { patient_id } = req.query;
    
    // If doctor/worker requests specific patient, allow it. Otherwise return own.
    const targetId = (user.role !== 'patient' && patient_id) ? patient_id : user.id;
    
    const metrics = db.prepare("SELECT * FROM health_metrics WHERE patient_id = ? ORDER BY recorded_at ASC").all(targetId);
    res.json(metrics);
  });

  app.post("/api/metrics", authenticateToken, (req: Request, res: Response) => {
    const { type, value, unit, patient_id } = req.body;
    const user = (req as any).user;
    
    // Health workers can submit for patients
    const targetId = (user.role === 'worker' && patient_id) ? patient_id : user.id;

    try {
      const result = db.prepare("INSERT INTO health_metrics (patient_id, type, value, unit) VALUES (?, ?, ?, ?)").run(targetId, type, value, unit);
      res.json({ id: result.lastInsertRowid, success: true });
    } catch (err) {
      res.status(500).json({ error: "Failed to record metric" });
    }
  });

  // Medical Records
  app.get("/api/records", authenticateToken, (req: Request, res: Response) => {
    const user = (req as any).user;
    const { patient_id } = req.query;

    let stmt;
    if (user.role === 'patient') {
      stmt = db.prepare("SELECT m.*, u.name as doctor_name FROM medical_records m JOIN users u ON m.doctor_id = u.id WHERE m.patient_id = ? ORDER BY created_at DESC");
      res.json(stmt.all(user.id));
    } else if (user.role === 'doctor') {
      if (patient_id) {
        // Doctor viewing specific patient's records
        stmt = db.prepare("SELECT m.*, u.name as doctor_name FROM medical_records m JOIN users u ON m.doctor_id = u.id WHERE m.patient_id = ? ORDER BY created_at DESC");
        res.json(stmt.all(patient_id));
      } else {
        // Doctor viewing records they created
        stmt = db.prepare("SELECT m.*, u.name as patient_name FROM medical_records m JOIN users u ON m.patient_id = u.id WHERE m.doctor_id = ? ORDER BY created_at DESC");
        res.json(stmt.all(user.id));
      }
    } else {
      res.status(403).json({ error: "Unauthorized" });
    }
  });

  app.post("/api/records", authenticateToken, (req: Request, res: Response) => {
    const { patient_id, diagnosis, prescription } = req.body;
    const user = (req as any).user;
    if (user.role !== 'doctor') return res.status(403).json({ error: "Only doctors can add records" });

    try {
      const result = db.prepare("INSERT INTO medical_records (patient_id, doctor_id, diagnosis, prescription) VALUES (?, ?, ?, ?)").run(patient_id, user.id, diagnosis, prescription);
      res.json({ id: result.lastInsertRowid, success: true });
    } catch (err) {
      res.status(500).json({ error: "Failed to add record" });
    }
  });

  // AI Analysis
  app.post("/api/ai/analyze", authenticateToken, async (req: Request, res: Response) => {
    const { metrics } = req.body;
    // In a real app, we would call Gemini here.
    // Since I cannot easily import GoogleGenAI in this single file without proper setup (package is installed though),
    // I will mock a simple heuristic response or try to use it if I can import it.
    // Let's try to use it since it is installed.
    
    try {
      // Dynamic import to avoid build issues if not set up in tsconfig for server
      const { GoogleGenAI } = await import("@google/genai");
      
      // Try multiple common environment variable names for the API key
      let apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || process.env.API_KEY || "";
      apiKey = apiKey.trim();
      
      // Check if key looks valid (starts with AIza)
      const isValidKey = apiKey.startsWith("AIza");
      
      if (!apiKey || !isValidKey) {
         console.warn("AI Warning: Invalid or missing API Key. Using heuristic response.");
         // Use smart heuristic analysis
         return res.json(analyzeMetricsRuleBased(metrics));
      }

      const ai = new GoogleGenAI({ apiKey });
      
      const prompt = `
        Analyze these patient health metrics and provide a risk assessment (Low, Medium, High) and a brief recommendation.
        Metrics: ${JSON.stringify(metrics)}
        Output JSON format: { "risk": "Level", "analysis": "Brief explanation" }
      `;

      try {
        const response = await ai.models.generateContent({
            model: "gemini-flash-latest",
            contents: prompt,
            config: {
                responseMimeType: "application/json"
            }
        });

        const text = response.text;
        const jsonStr = text?.replace(/```json/g, '').replace(/```/g, '').trim();
        res.json(JSON.parse(jsonStr || '{}'));
      } catch (apiError: any) {
         console.error("AI API Call Failed:", apiError);
         // Fallback if the API call itself fails (e.g. quota, network)
         return res.json(analyzeMetricsRuleBased(metrics));
      }

    } catch (error: any) {
      console.error("AI Error:", error);
      // Fallback heuristic
      res.json({ 
        risk: "Medium", 
        analysis: `AI analysis failed: ${error.message}. Based on basic heuristics, please monitor vitals closely.` 
      });
    }
  });

  // Users (for doctors to see patients, and patients to see doctors)
  app.get("/api/users", authenticateToken, (req: Request, res: Response) => {
    const user = (req as any).user;
    
    // Patients can only see doctors
    if (user.role === 'patient' && req.query.role !== 'doctor') {
        return res.status(403).json({ error: "Unauthorized" });
    }
    
    if (user.role === 'doctor' && req.query.role === 'patient') {
      // Enriched query for doctors viewing patients
      const stmt = db.prepare(`
        SELECT 
          u.id, u.name, u.email, u.role, u.age,
          (SELECT COUNT(*) FROM appointments WHERE patient_id = u.id) as treatment_count,
          (SELECT diagnosis FROM medical_records WHERE patient_id = u.id ORDER BY created_at DESC LIMIT 1) as latest_problem
        FROM users u
        WHERE u.role = 'patient'
      `);
      return res.json(stmt.all());
    }
    
    const roleFilter = req.query.role ? "WHERE role = ?" : "";
    const stmt = db.prepare(`SELECT id, name, email, role, age FROM users ${roleFilter}`);
    const users = req.query.role ? stmt.all(req.query.role) : stmt.all();
    res.json(users);
  });

  // Get single user details (for patient profile)
  app.get("/api/users/:id", authenticateToken, (req: Request, res: Response) => {
    const user = (req as any).user;
    const { id } = req.params;

    // Only doctors or the user themselves can view details
    if (user.role !== 'doctor' && user.id !== Number(id)) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const patient = db.prepare("SELECT id, name, email, role, age FROM users WHERE id = ?").get(id);
    if (!patient) return res.status(404).json({ error: "User not found" });

    res.json(patient);
  });

  // --- Vite Middleware ---
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    // Serve static files in production
    const distPath = path.resolve(__dirname, "dist");
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get("*", (req, res) => {
        res.sendFile(path.join(distPath, "index.html"));
      });
    }
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
