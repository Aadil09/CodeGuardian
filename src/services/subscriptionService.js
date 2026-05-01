'use strict';

const { Op } = require('sequelize');
const { Plan, Feature, PlanFeature, UserSubscription, UsageTracking } = require('../models');
const { createError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

// ─── Period helpers ───────────────────────────────────────────────────────────

/**
 * Returns { periodStart, periodEnd } for the current calendar month.
 * Usage is reset implicitly each month — a new row is created when the period changes.
 */
function getCurrentPeriod() {
  const now = new Date();
  const periodStart = new Date(now.getFullYear(), now.getMonth(), 1)
    .toISOString()
    .slice(0, 10); // 'YYYY-MM-01'
  const periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0)
    .toISOString()
    .slice(0, 10); // 'YYYY-MM-DD' (last day)
  return { periodStart, periodEnd };
}

// ─── Plan queries ─────────────────────────────────────────────────────────────

/**
 * Returns all active plans ordered by sortOrder, each with their full feature list.
 */
async function getPlansWithFeatures() {
  const plans = await Plan.findAll({
    where: { isActive: true },
    order: [['sortOrder', 'ASC']],
    include: [
      {
        model: PlanFeature,
        as: 'planFeatures',
        where: { isEnabled: true },
        required: false,
        include: [{ model: Feature, as: 'feature', where: { isActive: true }, required: false }],
      },
    ],
  });

  return plans.map(formatPlan);
}

function formatPlan(plan) {
  const p = plan.get({ plain: true });
  p.planFeatures = (p.planFeatures || [])
    .filter(pf => pf.feature)
    .sort((a, b) => (a.feature.sortOrder ?? 0) - (b.feature.sortOrder ?? 0));
  return p;
}

// ─── User subscription ────────────────────────────────────────────────────────

/**
 * Returns the user's currently active subscription (plan + features).
 * Falls back to the Basic plan if no subscription row exists yet.
 */
async function getUserSubscription(userId) {
  let subscription = await UserSubscription.findOne({
    where: { userId, status: 'active' },
    order: [['createdAt', 'DESC']],
    include: [
      {
        model: Plan,
        as: 'plan',
        include: [
          {
            model: PlanFeature,
            as: 'planFeatures',
            where: { isEnabled: true },
            required: false,
            include: [{ model: Feature, as: 'feature', where: { isActive: true }, required: false }],
          },
        ],
      },
    ],
  });

  // Auto-heal: assign Basic plan if user somehow has no subscription
  if (!subscription) {
    subscription = await assignBasicPlan(userId);
    if (!subscription) throw createError('No subscription found and Basic plan is not configured', 500);

    // Re-fetch with associations
    subscription = await UserSubscription.findByPk(subscription.id, {
      include: [
        {
          model: Plan,
          as: 'plan',
          include: [
            {
              model: PlanFeature,
              as: 'planFeatures',
              where: { isEnabled: true },
              required: false,
              include: [{ model: Feature, as: 'feature', where: { isActive: true }, required: false }],
            },
          ],
        },
      ],
    });
  }

  return formatSubscription(subscription);
}

function formatSubscription(sub) {
  const s = sub.get({ plain: true });
  if (s.plan && s.plan.planFeatures) {
    s.plan.planFeatures = s.plan.planFeatures
      .filter(pf => pf.feature)
      .sort((a, b) => (a.feature.sortOrder ?? 0) - (b.feature.sortOrder ?? 0));
  }
  return s;
}

/**
 * Assigns the Basic (free) plan to a user. Idempotent — skips if already active.
 */
async function assignBasicPlan(userId) {
  const basicPlan = await Plan.findOne({ where: { slug: 'basic', isActive: true } });
  if (!basicPlan) {
    logger.warn('Basic plan not found in database — run the subscription seeder');
    return null;
  }

  // Avoid duplicate active subscription
  const existing = await UserSubscription.findOne({ where: { userId, status: 'active' } });
  if (existing) return existing;

  return UserSubscription.create({
    userId,
    planId: basicPlan.id,
    status: 'active',
    startedAt: new Date(),
    expiresAt: null, // Basic plan never expires
  });
}

// ─── Subscribe / upgrade / downgrade ─────────────────────────────────────────

/**
 * Subscribes a user to a plan.
 *   - Cancels any existing active subscription first
 *   - Creates a new active subscription
 *   - Determines expiry: null for Basic (lifetime), 30 days for paid plans
 */
async function subscribeToPlan(userId, planId) {
  const plan = await Plan.findOne({ where: { id: planId, isActive: true } });
  if (!plan) throw createError('Plan not found or inactive', 404);

  // Fetch current active subscription (if any)
  const current = await UserSubscription.findOne({ where: { userId, status: 'active' } });

  const previousPlanId = current ? current.planId : null;

  // Nothing to do if already on this plan
  if (current && current.planId === planId) {
    throw createError('You are already subscribed to this plan', 409);
  }

  // Cancel the existing subscription
  if (current) {
    current.status = 'cancelled';
    current.cancelledAt = new Date();
    await current.save();
  }

  // Free plan: no expiry. Paid plans: 30-day billing cycle (simulated — no payment)
  const expiresAt = plan.price > 0
    ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    : null;

  const newSub = await UserSubscription.create({
    userId,
    planId,
    status: 'active',
    startedAt: new Date(),
    expiresAt,
    previousPlanId,
  });

  logger.info(`User ${userId} subscribed to plan "${plan.name}" (id=${plan.id})`);

  return {
    subscription: newSub,
    plan: plan.get({ plain: true }),
    previousPlanId,
  };
}

// ─── Feature access checking ──────────────────────────────────────────────────

/**
 * Checks whether a user is allowed to use a feature right now.
 *
 * Returns:
 * {
 *   allowed:     boolean,
 *   feature:     { key, name, type, unit },
 *   limit:       number | boolean | string   (raw configured limit)
 *   used:        number                      (only for 'limit' type)
 *   remaining:   number                      (-1 = unlimited)
 *   isUnlimited: boolean
 * }
 */
async function checkFeatureAccess(userId, featureKey) {
  const feature = await Feature.findOne({ where: { key: featureKey, isActive: true } });
  if (!feature) throw createError(`Unknown feature: ${featureKey}`, 400);

  // Get user's active plan
  const sub = await UserSubscription.findOne({ where: { userId, status: 'active' } });
  if (!sub) {
    // No subscription → deny (shouldn't normally happen; seeder assigns Basic on register)
    return buildDeniedAccess(feature, 0);
  }

  const planFeature = await PlanFeature.findOne({
    where: { planId: sub.planId, featureId: feature.id, isEnabled: true },
  });

  if (!planFeature) {
    // Feature not configured for this plan → deny
    return buildDeniedAccess(feature, 0);
  }

  const parsedValue = planFeature.getParsedValue(feature.type);

  // ── Boolean feature ───────────────────────────────────────────────────────
  if (feature.type === 'boolean') {
    return {
      allowed: parsedValue === true,
      feature: featurePublic(feature),
      limit: parsedValue,
      used: null,
      remaining: null,
      isUnlimited: false,
    };
  }

  // ── Enum feature ──────────────────────────────────────────────────────────
  if (feature.type === 'enum') {
    return {
      allowed: true,
      feature: featurePublic(feature),
      limit: parsedValue,
      used: null,
      remaining: null,
      isUnlimited: false,
      enumValue: parsedValue,
    };
  }

  // ── Limit feature ─────────────────────────────────────────────────────────
  const limit = parsedValue; // number, -1 = unlimited

  if (limit === -1) {
    return {
      allowed: true,
      feature: featurePublic(feature),
      limit: -1,
      used: await getMonthlyUsage(userId, feature.id),
      remaining: -1,
      isUnlimited: true,
    };
  }

  if (limit === 0) return buildDeniedAccess(feature, 0);

  const used = await getMonthlyUsage(userId, feature.id);
  const remaining = Math.max(0, limit - used);

  return {
    allowed: used < limit,
    feature: featurePublic(feature),
    limit,
    used,
    remaining,
    isUnlimited: false,
  };
}

function buildDeniedAccess(feature, limit) {
  return {
    allowed: false,
    feature: featurePublic(feature),
    limit,
    used: null,
    remaining: 0,
    isUnlimited: false,
  };
}

function featurePublic(feature) {
  return {
    id: feature.id,
    key: feature.key,
    name: feature.name,
    type: feature.type,
    unit: feature.unit,
  };
}

// ─── Usage tracking ───────────────────────────────────────────────────────────

/**
 * Returns the current month's usage count for (userId, featureId).
 */
async function getMonthlyUsage(userId, featureId) {
  const { periodStart } = getCurrentPeriod();
  const record = await UsageTracking.findOne({ where: { userId, featureId, periodStart } });
  return record ? record.usageCount : 0;
}

/**
 * Increments usage count by 1 for the current month.
 * Uses upsert semantics — safe for concurrent calls.
 */
async function trackUsage(userId, featureKey) {
  const feature = await Feature.findOne({ where: { key: featureKey, isActive: true } });
  if (!feature) throw createError(`Unknown feature: ${featureKey}`, 400);

  // Only 'limit' type features have meaningful usage tracking
  if (feature.type !== 'limit') return null;

  const { periodStart, periodEnd } = getCurrentPeriod();

  const [record] = await UsageTracking.findOrCreate({
    where: { userId, featureId: feature.id, periodStart },
    defaults: { periodEnd, usageCount: 0, lastUsedAt: new Date() },
  });

  record.usageCount += 1;
  record.lastUsedAt = new Date();
  await record.save();

  logger.debug(`Usage tracked: user=${userId} feature=${featureKey} count=${record.usageCount}`);
  return record;
}

/**
 * Returns all feature usage stats for a user in the current month,
 * enriched with plan limits so the UI can show "5 of 20 used".
 */
async function getUserUsageStats(userId) {
  const { periodStart, periodEnd } = getCurrentPeriod();

  // Get active subscription plan features
  const sub = await UserSubscription.findOne({ where: { userId, status: 'active' } });
  if (!sub) return { periodStart, periodEnd, usage: [] };

  const planFeatures = await PlanFeature.findAll({
    where: { planId: sub.planId, isEnabled: true },
    include: [{ model: Feature, as: 'feature', where: { isActive: true }, required: true }],
    order: [[{ model: Feature, as: 'feature' }, 'sortOrder', 'ASC']],
  });

  // Get all usage records for this period
  const usageRecords = await UsageTracking.findAll({
    where: { userId, periodStart },
  });

  const usageMap = {};
  usageRecords.forEach(r => { usageMap[r.featureId] = r.usageCount; });

  const usage = planFeatures.map(pf => {
    const feature = pf.feature;
    const parsedValue = pf.getParsedValue(feature.type);
    const used = usageMap[feature.id] ?? 0;

    let remaining = null;
    let isUnlimited = false;

    if (feature.type === 'limit') {
      const limit = parsedValue;
      isUnlimited = limit === -1;
      remaining = isUnlimited ? -1 : Math.max(0, limit - used);
    }

    return {
      featureId: feature.id,
      featureKey: feature.key,
      featureName: feature.name,
      type: feature.type,
      unit: feature.unit,
      limit: parsedValue,
      used: feature.type === 'limit' ? used : null,
      remaining,
      isUnlimited,
      periodStart,
      periodEnd,
    };
  });

  return { periodStart, periodEnd, usage };
}

/**
 * Returns the raw parsed plan-feature value for a user without usage tracking.
 * Useful for configuration checks (e.g. scan type, queue priority).
 * Returns null if the feature or subscription is not found.
 */
async function getPlanFeatureValue(userId, featureKey) {
  const feature = await Feature.findOne({ where: { key: featureKey, isActive: true } });
  if (!feature) return null;

  const sub = await UserSubscription.findOne({ where: { userId, status: 'active' } });
  if (!sub) return null;

  const planFeature = await PlanFeature.findOne({
    where: { planId: sub.planId, featureId: feature.id, isEnabled: true },
  });
  if (!planFeature) return null;

  return planFeature.getParsedValue(feature.type);
}

module.exports = {
  getPlansWithFeatures,
  getUserSubscription,
  assignBasicPlan,
  subscribeToPlan,
  checkFeatureAccess,
  trackUsage,
  getUserUsageStats,
  getCurrentPeriod,
  getPlanFeatureValue,
};
