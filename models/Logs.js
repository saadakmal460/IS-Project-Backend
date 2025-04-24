// models/Log.js
const mongoose = require("mongoose");

const LogSchema = new mongoose.Schema({
  userIp: String,
  userAgent: String,
  endpoint: String,
  method: String,
  timestamp: {
    type: Date,
    default: Date.now,
  },
  statusCode: Number,
  message: String,
  isSuspicious: {
    type: Boolean,
  },
});

module.exports = mongoose.model("Log", LogSchema);
