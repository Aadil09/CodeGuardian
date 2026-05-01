'use strict';

const User             = require('./User');
const Scan             = require('./Scan');
const Report           = require('./Report');
const Otp              = require('./Otp');
const Plan             = require('./Plan');
const Feature          = require('./Feature');
const PlanFeature      = require('./PlanFeature');
const UserSubscription = require('./UserSubscription');
const UsageTracking    = require('./UsageTracking');

// ── Core: User → Scans ───────────────────────────────────────────────────────
User.hasMany(Scan, { foreignKey: 'userId', as: 'scans', onDelete: 'CASCADE' });
Scan.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// ── Core: User → Reports ─────────────────────────────────────────────────────
User.hasMany(Report, { foreignKey: 'userId', as: 'reports', onDelete: 'CASCADE' });
Report.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// ── Core: Scan → Report (via scanId string, not PK) ──────────────────────────
Scan.hasOne(Report, { foreignKey: 'scanId', sourceKey: 'scanId', as: 'report', onDelete: 'CASCADE' });
Report.belongsTo(Scan, { foreignKey: 'scanId', targetKey: 'scanId', as: 'scan' });

// ── Subscription: Plan ↔ Features (many-to-many via PlanFeature) ─────────────
Plan.belongsToMany(Feature, { through: PlanFeature, foreignKey: 'planId', as: 'features' });
Feature.belongsToMany(Plan, { through: PlanFeature, foreignKey: 'featureId', as: 'plans' });

// Direct associations for eager loading with the join table row
Plan.hasMany(PlanFeature, { foreignKey: 'planId', as: 'planFeatures' });
PlanFeature.belongsTo(Plan, { foreignKey: 'planId', as: 'plan' });
PlanFeature.belongsTo(Feature, { foreignKey: 'featureId', as: 'feature' });
Feature.hasMany(PlanFeature, { foreignKey: 'featureId', as: 'planFeatures' });

// ── Subscription: User → UserSubscription → Plan ─────────────────────────────
User.hasMany(UserSubscription, { foreignKey: 'userId', as: 'subscriptions', onDelete: 'CASCADE' });
UserSubscription.belongsTo(User, { foreignKey: 'userId', as: 'user' });
UserSubscription.belongsTo(Plan, { foreignKey: 'planId', as: 'plan' });
Plan.hasMany(UserSubscription, { foreignKey: 'planId', as: 'subscriptions' });

// ── Subscription: User → UsageTracking ───────────────────────────────────────
User.hasMany(UsageTracking, { foreignKey: 'userId', as: 'usageRecords', onDelete: 'CASCADE' });
UsageTracking.belongsTo(User, { foreignKey: 'userId', as: 'user' });
UsageTracking.belongsTo(Feature, { foreignKey: 'featureId', as: 'feature' });
Feature.hasMany(UsageTracking, { foreignKey: 'featureId', as: 'usageRecords' });

module.exports = {
  User, Scan, Report, Otp,
  Plan, Feature, PlanFeature, UserSubscription, UsageTracking,
};
