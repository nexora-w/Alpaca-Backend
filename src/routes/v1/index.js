const express = require('express');
const healthRoutes = require('./health.routes');
const walletRoutes = require('./wallet.routes');

const router = express.Router();

router.use('/health', healthRoutes);
router.use('/wallet', walletRoutes);

module.exports = router;

