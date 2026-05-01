'use strict';

const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class PlanFeature extends Model {
  /**
   * Returns the typed parsed value:
   *   'limit'   → number (-1 = unlimited)
   *   'boolean' → boolean
   *   'enum'    → string
   */
  getParsedValue(featureType) {
    switch (featureType) {
      case 'limit':   return parseInt(this.value, 10);
      case 'boolean': return this.value === 'true';
      default:        return this.value;
    }
  }
}

PlanFeature.init(
  {
    id: {
      type: DataTypes.INTEGER.UNSIGNED,
      autoIncrement: true,
      primaryKey: true,
    },
    planId: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
    },
    featureId: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
    },
    value: {
      // All limits stored as strings for uniformity:
      //   numeric limit  → '5', '50', '-1' (unlimited)
      //   boolean flag   → 'true' / 'false'
      //   enum value     → 'basic' / 'advanced'
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    isEnabled: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
  },
  {
    sequelize,
    modelName: 'PlanFeature',
    tableName: 'plan_features',
    indexes: [
      // A plan can configure each feature exactly once
      { unique: true, fields: ['planId', 'featureId'] },
    ],
  }
);

module.exports = PlanFeature;
