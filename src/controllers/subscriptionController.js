'use strict';

const Joi = require('joi');
const subscriptionService = require('../services/subscriptionService');
const { createError } = require('../middleware/errorHandler');

// ─── GET /api/subscription/plans ─────────────────────────────────────────────
// Public — no auth required. Returns all active plans with feature details.
async function getPlans(req, res, next) {
  try {
    const plans = await subscriptionService.getPlansWithFeatures();
    res.json({ success: true, data: { plans } });
  } catch (err) {
    next(err);
  }
}

// ─── GET /api/subscription/current ───────────────────────────────────────────
// Returns the authenticated user's active subscription + plan features.
async function getCurrentSubscription(req, res, next) {
  try {
    const subscription = await subscriptionService.getUserSubscription(req.user.id);
    res.json({ success: true, data: { subscription } });
  } catch (err) {
    next(err);
  }
}

// ─── POST /api/subscription/subscribe ────────────────────────────────────────
// Subscribe / upgrade / downgrade to a plan.
// Body: { planId: number }
async function subscribe(req, res, next) {
  try {
    const schema = Joi.object({ planId: Joi.number().integer().positive().required() });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const result = await subscriptionService.subscribeToPlan(req.user.id, value.planId);

    const action = result.previousPlanId ? 'Plan changed' : 'Subscribed';
    res.status(201).json({
      success: true,
      message: `${action} to ${result.plan.name} successfully`,
      data: result,
    });
  } catch (err) {
    next(err);
  }
}

// ─── GET /api/subscription/usage ─────────────────────────────────────────────
// Returns current-month usage stats for every feature on the user's plan.
async function getUsageStats(req, res, next) {
  try {
    const stats = await subscriptionService.getUserUsageStats(req.user.id);
    res.json({ success: true, data: stats });
  } catch (err) {
    next(err);
  }
}

// ─── POST /api/subscription/usage/track ──────────────────────────────────────
// Manually record one unit of feature consumption.
// Primarily called by featureGuard after a successful action.
// Body: { featureKey: string }
async function trackUsage(req, res, next) {
  try {
    const schema = Joi.object({ featureKey: Joi.string().max(100).required() });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const record = await subscriptionService.trackUsage(req.user.id, value.featureKey);
    res.json({ success: true, data: { usageCount: record?.usageCount ?? null } });
  } catch (err) {
    next(err);
  }
}

// ─── GET /api/subscription/check/:featureKey ─────────────────────────────────
// Check if the calling user can currently access a feature.
// Useful for the frontend to show/hide UI elements without hitting actual APIs.
async function checkFeatureAccess(req, res, next) {
  try {
    const { featureKey } = req.params;
    if (!featureKey || featureKey.length > 100) {
      throw createError('Invalid feature key', 400);
    }
    const access = await subscriptionService.checkFeatureAccess(req.user.id, featureKey);
    res.json({ success: true, data: access });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getPlans,
  getCurrentSubscription,
  subscribe,
  getUsageStats,
  trackUsage,
  checkFeatureAccess,
};
