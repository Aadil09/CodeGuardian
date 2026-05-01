'use strict';

const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class UserSubscription extends Model {
  get isActive() {
    if (this.status !== 'active') return false;
    if (!this.expiresAt) return true; // lifetime / no expiry
    return new Date(this.expiresAt) > new Date();
  }
}

UserSubscription.init(
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
    planId: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
    },
    status: {
      type: DataTypes.ENUM('active', 'cancelled', 'expired', 'pending'),
      defaultValue: 'active',
    },
    startedAt: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
    expiresAt: {
      // NULL = no expiry (used for Basic/free lifetime plans)
      type: DataTypes.DATE,
      allowNull: true,
      defaultValue: null,
    },
    cancelledAt: {
      type: DataTypes.DATE,
      allowNull: true,
      defaultValue: null,
    },
    previousPlanId: {
      // Tracks the plan the user upgraded/downgraded from
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: true,
      defaultValue: null,
    },
    metadata: {
      // Reserved for future payment integration:
      // { stripeCustomerId, stripeSubscriptionId, paymentMethodId, ... }
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: null,
    },
  },
  {
    sequelize,
    modelName: 'UserSubscription',
    tableName: 'user_subscriptions',
    indexes: [
      { fields: ['userId', 'status'] },
    ],
  }
);

module.exports = UserSubscription;
