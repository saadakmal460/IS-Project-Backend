const mongoose = require("mongoose");

const BlockedIpSchema = new mongoose.Schema({
  ipAddress: { type: String, required: true, unique: true },
  reason: { type: String, required: true },
  blockedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("BlockedIP", BlockedIpSchema);
