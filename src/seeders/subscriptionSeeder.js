'use strict';

const { Plan, Feature, PlanFeature } = require('../models');
const logger = require('../utils/logger');

/**
 * Seeds the plans, features, and plan_features tables.
 * Fully idempotent — safe to call on every server start.
 */
async function seedSubscriptions() {
  try {
    await seedPlans();
    await seedFeatures();
    await seedPlanFeatures();
    logger.info('Subscription seed completed successfully');
  } catch (err) {
    logger.error('Subscription seed failed:', err.message);
    throw err;
  }
}

// ─── Plans ────────────────────────────────────────────────────────────────────

async function seedPlans() {
  const plans = [
    {
      name: 'Basic',
      slug: 'basic',
      description: 'Free tier for individual developers. Get started with core security scanning.',
      price: 0.00,
      billingCycle: 'monthly',
      isActive: true,
      sortOrder: 1,
      metadata: {
        badge: null,
        highlights: ['5 PR reviews/month', 'Basic security scans', 'Community support'],
      },
    },
    {
      name: 'Silver',
      slug: 'silver',
      description: 'For small teams that need more power. Advanced scans, exports, and priority support.',
      price: 29.00,
      billingCycle: 'monthly',
      isActive: true,
      sortOrder: 2,
      metadata: {
        badge: 'Popular',
        highlights: ['50 PR reviews/month', 'Advanced security scans', 'Report exports', 'Priority support'],
      },
    },
    {
      name: 'Gold',
      slug: 'gold',
      description: 'Unlimited everything for large teams. Priority processing and full feature access.',
      price: 79.00,
      billingCycle: 'monthly',
      isActive: true,
      sortOrder: 3,
      metadata: {
        badge: 'Enterprise',
        highlights: ['Unlimited PR reviews', 'Advanced security scans', 'Priority queue', 'Full export access'],
      },
    },
  ];

  for (const planData of plans) {
    const existing = await Plan.findOne({ where: { slug: planData.slug } });
    if (!existing) {
      await Plan.create(planData);
      logger.info(`Seeded plan: ${planData.name}`);
    }
  }
}

// ─── Features ─────────────────────────────────────────────────────────────────

async function seedFeatures() {
  const features = [
    {
      key: 'pr_reviews_per_month',
      name: 'PR Reviews per Month',
      description: 'Number of pull request security reviews allowed each month.',
      type: 'limit',
      unit: 'reviews',
      isActive: true,
      sortOrder: 1,
    },
    {
      key: 'security_scan_type',
      name: 'Security Scan Type',
      description: 'Depth of the security scan: basic (OWASP Top 5) or advanced (full OWASP Top 10 + ESLint + npm audit).',
      type: 'enum',
      unit: null,
      isActive: true,
      sortOrder: 2,
    },
    {
      key: 'priority_processing',
      name: 'Priority Processing',
      description: 'Scans are placed at the front of the queue for faster results.',
      type: 'boolean',
      unit: null,
      isActive: true,
      sortOrder: 3,
    },
    {
      key: 'report_export',
      name: 'Report Export',
      description: 'Download security reports as PDF or CSV.',
      type: 'boolean',
      unit: null,
      isActive: true,
      sortOrder: 4,
    },
  ];

  for (const featureData of features) {
    const existing = await Feature.findOne({ where: { key: featureData.key } });
    if (!existing) {
      await Feature.create(featureData);
      logger.info(`Seeded feature: ${featureData.key}`);
    }
  }
}

// ─── Plan ↔ Feature limits ────────────────────────────────────────────────────

async function seedPlanFeatures() {
  const [basic, silver, gold] = await Promise.all([
    Plan.findOne({ where: { slug: 'basic' } }),
    Plan.findOne({ where: { slug: 'silver' } }),
    Plan.findOne({ where: { slug: 'gold' } }),
  ]);

  const features = await Feature.findAll();
  const featureMap = {};
  features.forEach(f => { featureMap[f.key] = f.id; });

  // Each entry: [featureKey, basicValue, silverValue, goldValue]
  // Limit:   number string; '-1' = unlimited
  // Boolean: 'true' / 'false'
  // Enum:    the enum string value
  const matrix = [
    ['pr_reviews_per_month', '5',       '50',        '-1'],
    ['security_scan_type',   'basic',   'advanced',  'advanced'],
    ['priority_processing',  'false',   'true',      'true'],
    ['report_export',        'false',   'true',      'true'],
  ];

  const planSlugMap = { basic, silver, gold };

  for (const [featureKey, basicVal, silverVal, goldVal] of matrix) {
    const featureId = featureMap[featureKey];
    if (!featureId) { logger.warn(`Feature "${featureKey}" not found — skipping`); continue; }

    const entries = [
      { plan: basic,  value: basicVal  },
      { plan: silver, value: silverVal },
      { plan: gold,   value: goldVal   },
    ];

    for (const { plan, value } of entries) {
      if (!plan) continue;
      const existing = await PlanFeature.findOne({ where: { planId: plan.id, featureId } });
      if (!existing) {
        await PlanFeature.create({ planId: plan.id, featureId, value, isEnabled: true });
        logger.info(`Seeded plan_feature: ${plan.slug}.${featureKey} = ${value}`);
      }
    }
  }
}

module.exports = { seedSubscriptions };
