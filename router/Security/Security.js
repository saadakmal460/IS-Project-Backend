const express = require('express');
const { blockIp, GetLogs } = require('../../controllers/Security/Security');



const router = express.Router();


// Route to block an IP
router.post('/block-ip', blockIp);

router.get('/getLogs', GetLogs);


module.exports = router;
