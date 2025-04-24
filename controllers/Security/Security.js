
const BlockedIP = require("../../models/BlockedIP");
const Logs = require("../../models/Logs");


// Controller to block an IP
exports.blockIp = async (req, res) => {
  try {
    const { ipAddress, reason } = req.body;
    console.log('yes')
    // Validate that the IP address is in the correct format
    if (!ipAddress || !reason) {
      return res.status(400).json({ message: "IP address and reason are required" });
    }

    // Check if the IP is already blocked
    const existingBlockedIp = await BlockedIP.findOne({ ipAddress });
    if (existingBlockedIp) {
      return res.status(400).json({ message: "IP is already blocked" });
    }

    // Add the IP to the BlockedIps collection
    const newBlockedIp = new BlockedIP({
      ipAddress,
      reason,
    });

    await newBlockedIp.save();

    return res.status(201).json({
      message: `IP ${ipAddress} has been blocked successfully`,
      blockedIp: newBlockedIp,
    });
  } catch (error) {
    // Log detailed error on the server side for debugging
    console.error('Error blocking IP:', error); // This will show you the full error in the console

    // Send a 500 response with a more detailed error message
    return res.status(500).json({
      message: 'An error occurred while blocking the IP',
      error: error.message || 'Internal Server Error', // Include the error message
      stack: error.stack, // Optionally include stack trace for debugging (don't do this in production)
    });
  }
};


exports.GetLogs = async (req, res) => {

  try {
    const logs = await Logs.find().sort({ timestamp: -1 });
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch logs" });
  }

}