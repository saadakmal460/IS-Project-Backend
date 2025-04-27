const express = require('express');
const { summarize } = require('../../controllers/Summarizer/Summearizer');
const { auth } = require('../../Middleware/auth');



const router = express.Router();


// Route to block an IP
router.post('/summarize', auth ,  summarize);


module.exports = router;