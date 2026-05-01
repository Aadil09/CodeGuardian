'use strict';

const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class Scan extends Model {}

Scan.init(
  {
    id: {
      type: DataTypes.INTEGER.UNSIGNED,
      autoIncrement: true,
      primaryKey: true,
    },
    scanId: {
      type: DataTypes.STRING(36),
      allowNull: false,
      unique: 'idx_scans_scanId',
    },
    userId: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
    },
    projectId: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    projectName: {
      type: DataTypes.STRING(500),
      allowNull: true,
    },
    projectUrl: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    pullRequestId: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
    },
    pullRequestTitle: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    pullRequestUrl: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    sourceBranch: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    targetBranch: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    commitSha: {
      type: DataTypes.STRING(100),
      allowNull: true,
    },
    status: {
      type: DataTypes.ENUM('pending', 'queued', 'running', 'completed', 'failed', 'cancelled'),
      defaultValue: 'pending',
    },
    progress: {
      type: DataTypes.TINYINT.UNSIGNED,
      defaultValue: 0,
      validate: { min: 0, max: 100 },
    },
    startedAt: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    completedAt: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    durationMs: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: true,
    },
    errorMessage: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    jobId: {
      type: DataTypes.STRING(100),
      allowNull: true,
    },
    filesScanned: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    linesScanned: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
  },
  {
    sequelize,
    modelName: 'Scan',
    tableName: 'scans',
    indexes: [
      { fields: ['scanId'] },
      { fields: ['userId', 'status'] },
      { fields: ['userId', 'projectId'] },
    ],
  }
);

module.exports = Scan;
