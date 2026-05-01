'use strict';

const subscriptionService = require('../services/subscriptionService');
const logger = require('../utils/logger');

/**
 * featureGuard(featureKey, options)
 *
 * Express middleware factory that gates a route behind a subscription feature check.
 * Place after the `authenticate` middleware.
 *
 * Usage:
 *   router.post('/scan', authenticate, featureGuard('pr_reviews_per_month'), scanController.startScan)
 *
 * Options:
 *   trackOnSuccess {boolean} — if true, increments the usage counter after next() completes
 *                              Set to false when you want to track usage yourself (default: true)
 *
 * On success, attaches `req.featureAccess` with the access details so the handler
 * can read limit/remaining values (e.g. to configure scan depth).
 *
 * On failure, responds 403 with a structured error body:
 * {
 *   success: false,
 *   message: "...",
 *   data: { featureKey, limit, used, remaining, planName }
 * }
 */
function featureGuard(featureKey, { trackOnSuccess = true } = {}) {
  return async function (req, res, next) {
    try {
      const access = await subscriptionService.checkFeatureAccess(req.user.id, featureKey);

      if (!access.allowed) {
        const planInfo = await getPlanInfo(req.user.id);
        logger.info(
          `Feature blocked: user=${req.user.id} feature=${featureKey} ` +
          `used=${access.used} limit=${access.limit} plan=${planInfo?.name}`
        );

        return res.status(403).json({
          success: false,
          message: buildBlockMessage(access, featureKey, planInfo),
          data: {
            featureKey,
            limit: access.limit,
            used: access.used,
            remaining: access.remaining,
            planName: planInfo?.name,
            upgradeRequired: true,
          },
        });
      }

      // Attach access info to request so the route handler can use it
      req.featureAccess = access;

      if (trackOnSuccess) {
        // Intercept the response to track usage only after a 2xx response
        const originalJson = res.json.bind(res);
        res.json = function (body) {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            // Fire-and-forget — don't block the response
            subscriptionService
              .trackUsage(req.user.id, featureKey)
              .catch(err => logger.error(`Usage tracking failed for ${featureKey}:`, err.message));
          }
          return originalJson(body);
        };
      }

      next();
    } catch (err) {
      // Never block a request due to a guard error — log and continue
      logger.error(`featureGuard error for feature "${featureKey}":`, err.message);
      next();
    }
  };
}

function buildBlockMessage(access, featureKey, plan) {
  const planName = plan?.name ?? 'current';
  if (access.feature?.type === 'boolean') {
    return `This feature is not available on the ${planName} plan. Please upgrade to access it.`;
  }
  if (access.used !== null && access.limit !== null) {
    const unit = access.feature?.unit ?? 'uses';
    return (
      `You have used ${access.used} of ${access.limit} ${unit} on the ${planName} plan. ` +
      `Upgrade your plan to continue.`
    );
  }
  return `Feature "${featureKey}" is not available on the ${planName} plan. Please upgrade.`;
}

async function getPlanInfo(userId) {
  try {
    const { UserSubscription, Plan } = require('../models');
    const sub = await UserSubscription.findOne({
      where: { userId, status: 'active' },
      include: [{ model: Plan, as: 'plan' }],
    });
    return sub?.plan ?? null;
  } catch {
    return null;
  }
}

module.exports = featureGuard;
