'use strict';

const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { scanLimiter } = require('../middleware/rateLimiter');
const featureGuard = require('../middleware/featureGuard');
const scanController = require('../controllers/scanController');

router.use(authenticate);

// featureGuard checks pr_reviews_per_month before the scan is created.
// On a 2xx response it automatically increments the usage counter.
router.post('/', scanLimiter, featureGuard('pr_reviews_per_month'), scanController.startScan);
router.get('/',             scanController.listScans);
router.get('/:scanId',      scanController.getScanStatusController);
router.delete('/:scanId',   scanController.cancelScanController);

module.exports = router;
