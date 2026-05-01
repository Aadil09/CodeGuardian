'use strict';

const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class Plan extends Model {}

Plan.init(
  {
    id: {
      type: DataTypes.INTEGER.UNSIGNED,
      autoIncrement: true,
      primaryKey: true,
    },
    name: {
      type: DataTypes.STRING(50),
      allowNull: false,
      // Uniqueness enforced at application level (no constraint — consistent with User.email pattern)
    },
    slug: {
      type: DataTypes.STRING(50),
      allowNull: false,
      // e.g. 'basic', 'silver', 'gold'
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    price: {
      // Stored for future payment integration; 0.00 = free
      type: DataTypes.DECIMAL(10, 2),
      defaultValue: 0.0,
    },
    billingCycle: {
      type: DataTypes.ENUM('monthly', 'yearly', 'lifetime'),
      defaultValue: 'monthly',
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    sortOrder: {
      // Controls display order on pricing page
      type: DataTypes.INTEGER,
      defaultValue: 0,
    },
    metadata: {
      // Extensible JSON for future fields (e.g. stripe_price_id, highlights)
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: null,
    },
  },
  {
    sequelize,
    modelName: 'Plan',
    tableName: 'plans',
  }
);

module.exports = Plan;
