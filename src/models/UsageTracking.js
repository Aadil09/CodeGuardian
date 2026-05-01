'use strict';

const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class UsageTracking extends Model {}

UsageTracking.init(
  {
    id: {
      type: DataTypes.INTEGER.UNSIGNED,
      autoIncrement: true,
      primaryKey: true,
    },
    userId: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
    },
    featureId: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
    },
    periodStart: {
      // First day of the billing month, e.g. '2025-05-01'
      // Monthly reset is implicit — each new month creates a new row
      type: DataTypes.DATEONLY,
      allowNull: false,
    },
    periodEnd: {
      // Last day of the billing month, e.g. '2025-05-31'
      type: DataTypes.DATEONLY,
      allowNull: false,
    },
    usageCount: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    lastUsedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      defaultValue: null,
    },
  },
  {
    sequelize,
    modelName: 'UsageTracking',
    tableName: 'usage_tracking',
    indexes: [
      // One row per (user, feature, month) — prevents double-counting
      { unique: true, fields: ['userId', 'featureId', 'periodStart'] },
      { fields: ['userId', 'periodStart'] },
    ],
  }
);

module.exports = UsageTracking;
