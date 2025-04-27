const express = require('express');
const { blockIp, GetLogs, getBlockedIps, deleteBlockedIp } = require('../../controllers/Security/Security');
const { authorizeRoles, auth } = require('../../Middleware/auth');



const router = express.Router();


// Route to block an IP
router.post('/block-ip', auth , authorizeRoles('admin') ,  blockIp);

router.get('/getLogs', auth , authorizeRoles('admin') , GetLogs);

router.get('/getblockedips', auth , authorizeRoles('admin') , getBlockedIps);

router.delete('/unblock/:id', auth , authorizeRoles('admin') , deleteBlockedIp);




module.exports = router;
