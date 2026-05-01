'use strict';

const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const subscriptionController = require('../controllers/subscriptionController');

// Public — pricing page doesn't require login
router.get('/plans', subscriptionController.getPlans);

// All remaining routes require authentication
router.use(authenticate);

router.get('/current',            subscriptionController.getCurrentSubscription);
router.post('/subscribe',         subscriptionController.subscribe);
router.get('/usage',              subscriptionController.getUsageStats);
router.post('/usage/track',       subscriptionController.trackUsage);
router.get('/check/:featureKey',  subscriptionController.checkFeatureAccess);

module.exports = router;
