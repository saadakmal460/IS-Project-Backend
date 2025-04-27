
const BlockedIP = require("../../models/BlockedIP");
const Logs = require("../../models/Logs");


// Controller to block an IP
exports.blockIp = async (req, res) => {
  try {
    const { ipAddress, reason } = req.body;
    
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


exports.getBlockedIps = async (req, res) => {
  try {
    const blockedIps = await BlockedIP.find(); // Fetch all blocked IPs
    return res.status(200).json({
      message: 'Blocked IPs retrieved successfully',
      blockedIps,
    });
  } catch (error) {
    console.error('Error fetching blocked IPs:', error);
    return res.status(500).json({
      message: 'An error occurred while fetching blocked IPs',
      error: error.message || 'Internal Server Error',
    });
  }
};

exports.deleteBlockedIp = async (req, res) => {
  try {
    const { id } = req.params; // Get the ID from URL params

    if (!id) {
      return res.status(400).json({ message: "ID is required" });
    }

    const deletedIp = await BlockedIP.findByIdAndDelete(id);

    if (!deletedIp) {
      return res.status(404).json({ message: "Blocked IP not found" });
    }

    return res.status(200).json({
      message: `Blocked IP with ID ${id} has been deleted successfully`,
      deletedIp,
    });
  } catch (error) {
    console.error('Error deleting blocked IP:', error);
    return res.status(500).json({
      message: 'An error occurred while deleting the blocked IP',
      error: error.message || 'Internal Server Error',
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