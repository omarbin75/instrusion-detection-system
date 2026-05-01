import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import { createServer as createViteServer } from "vite";
import path from "path";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import fs from "fs";

// --- TYPES ---
interface Packet {
  id: string;
  timestamp: number;
  sourceIp: string;
  destIp: string;
  destPort: number;
  protocol: "TCP" | "UDP" | "ICMP" | "ARP";
  flags?: string[];
  macSource?: string;
  macDest?: string;
  payloadSize: number;
}

interface Alert {
  id: string;
  timestamp: number;
  type: string;
  sourceIp: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  description: string;
}

// --- CONFIG ---
const PORT = 3000;
const JWT_SECRET = "sentinel-super-secret-key";
const USERS_FILE = "./users.json";
const LOGS_FILE = "./alerts.json";

// In-memory storage for detection engine
const recentPackets: Packet[] = [];
const attackerStats: Record<string, { synCount: number; portHits: Set<number>; icmpCount: number; udpCount: number; lastSeen: number }> = {};
const blockedIps = new Set<string>();
const activeRules = {
  synFlood: true,
  portScan: true,
  bruteForce: true,
  icmpFlood: true,
  udpFlood: true,
  arpSpoof: true
};

// Thresholds
const THRESHOLDS = {
  SYN_FLOOD: 50, // SYNs per 5 seconds
  PORT_SCAN: 10,  // Unique ports per 10 seconds
  ICMP_FLOOD: 30, // ICMP per 5 seconds
  UDP_FLOOD: 100, // UDP per 5 seconds
  BRUTE_FORCE: 5,  // Login port (e.g. 22, 80, 443) hits from same IP
  WINDOW_MS: 10000
};

// --- CORE SERVER ---
async function startServer() {
  const app = express();
  const httpServer = createServer(app);
  const io = new Server(httpServer, {
    cors: { origin: "*" }
  });

  app.use(cors());
  app.use(express.json());

  // --- AUTH ENDPOINTS ---
  app.post("/api/auth/signup", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });
    
    let users = [];
    if (fs.existsSync(USERS_FILE)) users = JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
    
    if (users.find((u: any) => u.username === username)) return res.status(400).json({ error: "User exists" });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    fs.writeFileSync(USERS_FILE, JSON.stringify(users));
    
    res.json({ message: "User created" });
  });

  app.post("/api/auth/login", async (req, res) => {
    const { username, password } = req.body;
    if (!fs.existsSync(USERS_FILE)) return res.status(400).json({ error: "No users found" });
    
    const users = JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
    const user = users.find((u: any) => u.username === username);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "24h" });
    res.json({ token, username });
  });

  // --- LOGS API ---
  app.get("/api/alerts", (req, res) => {
    if (!fs.existsSync(LOGS_FILE)) return res.json([]);
    const logs = JSON.parse(fs.readFileSync(LOGS_FILE, "utf-8"));
    res.json(logs);
  });

  app.delete("/api/alerts", (req, res) => {
    fs.writeFileSync(LOGS_FILE, "[]");
    res.json({ message: "Logs cleared" });
  });

  // --- MONITORING LOGIC ---
  let isMonitoring = true;

  // Detection Engine
  const processPacket = (packet: Packet) => {
    if (!isMonitoring) return;
    
    const now = Date.now();
    recentPackets.push(packet);
    // Keep only last window
    while (recentPackets.length > 0 && recentPackets[0].timestamp < now - THRESHOLDS.WINDOW_MS) {
      recentPackets.shift();
    }

    const { sourceIp, protocol, flags, destPort } = packet;

    if (blockedIps.has(sourceIp)) return;

    if (!attackerStats[sourceIp]) {
      attackerStats[sourceIp] = { synCount: 0, portHits: new Set(), icmpCount: 0, udpCount: 0, lastSeen: now };
    }
    const stats = attackerStats[sourceIp];
    stats.lastSeen = now;

    // RULE: SYN Flood
    if (activeRules.synFlood && protocol === "TCP" && flags?.includes("SYN")) {
      stats.synCount++;
      if (stats.synCount > THRESHOLDS.SYN_FLOOD) {
        createAlert(sourceIp, "SYN Flood Attack", "CRITICAL");
        stats.synCount = 0; // cooldown
      }
    }

    // RULE: Port Scanning
    if (activeRules.portScan) {
      stats.portHits.add(destPort);
      if (stats.portHits.size > THRESHOLDS.PORT_SCAN) {
        createAlert(sourceIp, "Port Scanning Detected", "HIGH");
        stats.portHits.clear();
      }
    }

    // RULE: ICMP Flood
    if (activeRules.icmpFlood && protocol === "ICMP") {
      stats.icmpCount++;
      if (stats.icmpCount > THRESHOLDS.ICMP_FLOOD) {
        createAlert(sourceIp, "ICMP Flood Attack", "MEDIUM");
        stats.icmpCount = 0;
      }
    }

    // RULE: UDP Flood
    if (activeRules.udpFlood && protocol === "UDP") {
      stats.udpCount++;
      if (stats.udpCount > THRESHOLDS.UDP_FLOOD) {
        createAlert(sourceIp, "UDP Flood Attack", "MEDIUM");
        stats.udpCount = 0;
      }
    }

    // RULE: Brute Force (Simple check on common ports)
    if (activeRules.bruteForce && [22, 21, 23, 3389].includes(destPort)) {
        // High frequency hits on auth ports
        const windowPackets = recentPackets.filter(p => p.sourceIp === sourceIp && p.destPort === destPort);
        if (windowPackets.length > 10) {
            createAlert(sourceIp, "Brute Force Attempt", "HIGH");
        }
    }

    io.emit("packet", packet);
  };

  const createAlert = (sourceIp: string, type: string, severity: "CRITICAL" | "HIGH" | "MEDIUM") => {
    const alert: Alert = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      type,
      sourceIp,
      severity,
      description: `Detected ${type} originating from ${sourceIp}`
    };

    // Auto-block for High/Critical
    if (severity === "HIGH" || severity === "CRITICAL") {
      if (!blockedIps.has(sourceIp)) {
        blockedIps.add(sourceIp);
        console.log(`[IPS] Blocked IP: ${sourceIp} due to ${severity} alert.`);
        // Note: Real iptables would be called here: 
        // exec(`iptables -A INPUT -s ${sourceIp} -j DROP`)
        io.emit("ip_blocked", { ip: sourceIp, reason: type });
      }
    }

    // Store log
    let logs = [];
    if (fs.existsSync(LOGS_FILE)) logs = JSON.parse(fs.readFileSync(LOGS_FILE, "utf-8"));
    logs.unshift(alert);
    fs.writeFileSync(LOGS_FILE, JSON.stringify(logs.slice(0, 1000)));

    io.emit("alert", alert);
  };

  // --- TRAFFIC INGESTION / SNIFFER ---
  // Since we are in a container, we will capture traffic coming into our own server as "Real Traffic"
  // and also simulate environmental noise that a real NIC would see in a semi-active network.
  app.use((req, res, next) => {
    const packet: Packet = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      sourceIp: req.ip || "unknown",
      destIp: "127.0.0.1",
      destPort: PORT,
      protocol: "TCP",
      flags: ["ACK", "PSH"],
      payloadSize: JSON.stringify(req.body || {}).length + 500
    };
    processPacket(packet);
    next();
  });

  // Simulated real traffic to fill the dashboard when humans aren't clicking
  setInterval(() => {
    if (!isMonitoring) return;
    const protocols: any[] = ["TCP", "UDP", "ICMP", "ARP"];
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];
    const sourceIp = `192.168.1.${Math.floor(Math.random() * 254)}`;
    
    const packet: Packet = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      sourceIp,
      destIp: "10.0.0.5",
      destPort: [80, 443, 22, 53, 3000][Math.floor(Math.random() * 5)],
      protocol,
      flags: protocol === "TCP" ? ["SYN", "ACK"][Math.floor(Math.random() * 2) === 0 ? 0 : 1] ? ["SYN"] : ["ACK"] : undefined,
      payloadSize: Math.floor(Math.random() * 1500)
    };
    processPacket(packet);
  }, 500);

  // --- SOCKET CONTROL ---
  io.on("connection", (socket) => {
    socket.emit("monitoring_status", isMonitoring);
    socket.emit("blocked_ips", Array.from(blockedIps));
    
    socket.on("toggle_monitoring", (status: boolean) => {
      isMonitoring = status;
      io.emit("monitoring_status", isMonitoring);
    });

    socket.on("unblock_ip", (ip: string) => {
      blockedIps.delete(ip);
      io.emit("blocked_ips", Array.from(blockedIps));
    });
  });

  // --- VITE MIDDLEWARE ---
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
