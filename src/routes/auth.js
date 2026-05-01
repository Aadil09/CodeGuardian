'use strict';

const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const authController = require('../controllers/authController');

// ── Public auth ──────────────────────────────────────────────────
router.post('/register', authController.register);
router.post('/login', authLimiter, authController.login);

// ── Forgot password flow (public) ────────────────────────────────
router.post('/forgot-password/send-otp', authLimiter, authController.sendOtp);
router.post('/forgot-password/verify-otp', authController.verifyOtp);
router.post('/forgot-password/reset-password', authController.resetPassword);

// ── Authenticated profile ────────────────────────────────────────
router.get('/profile', authenticate, authController.getProfile);
router.put('/profile', authenticate, authController.updateProfile);
router.put('/profile/change-password', authenticate, authController.changePassword);

// ── Misc authenticated ───────────────────────────────────────────
router.post('/external-login', authenticate, authLimiter, authController.externalLogin);
router.put('/github-token', authenticate, authController.updateGithubToken);

module.exports = router;
