'use strict';

const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const featureGuard = require('../middleware/featureGuard');
const reportController = require('../controllers/reportController');

router.use(authenticate);
router.get('/stats', reportController.getStats);
router.get('/top-vulnerabilities', reportController.getTopVulnerabilities);
router.get('/', reportController.getReports);
router.get('/:scanId', reportController.getReport);
// report_export is a boolean plan feature — Basic plan gets 403, Silver/Gold pass through
router.get('/:scanId/export', featureGuard('report_export', { trackOnSuccess: false }), reportController.exportReport);
router.delete('/:scanId', reportController.deleteReport);

module.exports = router;
