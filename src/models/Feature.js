'use strict';

const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class Feature extends Model {}

Feature.init(
  {
    id: {
      type: DataTypes.INTEGER.UNSIGNED,
      autoIncrement: true,
      primaryKey: true,
    },
    key: {
      // Stable identifier used in code — never change after deployment
      // e.g. 'pr_reviews_per_month', 'security_scan_type'
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    name: {
      type: DataTypes.STRING(150),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    type: {
      // 'limit'   → numeric cap; value '-1' means unlimited
      // 'boolean' → feature on/off; value 'true'/'false'
      // 'enum'    → constrained string value (e.g. 'basic'/'advanced')
      type: DataTypes.ENUM('limit', 'boolean', 'enum'),
      allowNull: false,
      defaultValue: 'limit',
    },
    unit: {
      // Human-readable unit for display (e.g. 'reviews', 'lines', 'members')
      type: DataTypes.STRING(50),
      allowNull: true,
      defaultValue: null,
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    sortOrder: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
    },
  },
  {
    sequelize,
    modelName: 'Feature',
    tableName: 'features',
  }
);

module.exports = Feature;
