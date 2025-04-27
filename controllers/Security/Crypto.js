const { default: axios } = require("axios");

exports.getPublicKey = async (req, res) => {
    try {
      const response = await axios.get('http://localhost:8000/public-key');
      
      // Forward the response from the backend to the client
      res.status(200).json(response.data);
    } catch (error) {
      console.error('Error fetching public key:', error.message);
  
      res.status(500).json({ 
        message: 'Failed to fetch public key',
        error: error.message 
      });
    }
};