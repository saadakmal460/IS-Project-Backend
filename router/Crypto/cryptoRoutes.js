const express = require('express');
const { getPublicKey } = require('../../controllers/Security/Crypto');
const { auth } = require('../../Middleware/auth');




const router = express.Router();


// Route to block an IP
router.get('/public-key' , auth , getPublicKey);


module.exports = router;