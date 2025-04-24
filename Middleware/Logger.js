const BlockedIP = require("../models/BlockedIP");
const Logs = require("../models/Logs");


const logMiddleware = async (req, res, next) => {
    const requestStart = Date.now();
  
    // Check if the IP is blocked in the database
    const blockedIp = await BlockedIP.findOne({ ipAddress: req.ip });
    if (blockedIp) {
      return res.status(403).json({ message: "Your IP is blocked due to suspicious activity." });
    }
  
    res.on("finish", async () => {
      const requestEnd = Date.now();
      const requestDuration = (requestEnd - requestStart) / 1000; // in seconds
  
      // Simple rules for anomaly detection
      const suspiciousConditions = [
        requestDuration < 0.1, // suspiciously fast
        res.statusCode === 403 || res.statusCode === 401, // frequent auth issues
        req.originalUrl.includes("admin"), // probing admin routes
        req.method === "POST" && !req.body, // empty POST body
      ];
  
      const isSuspicious = suspiciousConditions.some(Boolean);
  
      // Log request data
      const log = new Logs({
        userIp: req.ip,
        userAgent: req.headers["user-agent"],
        endpoint: req.originalUrl,
        method: req.method,
        statusCode: res.statusCode,
        message: `${req.method} ${req.originalUrl}`,
        isSuspicious,
      });
  
      try {
        await log.save();
      } catch (err) {
        console.error("Failed to log request:", err);
      }

    });
  
    next();
  };
  

module.exports = logMiddleware;

