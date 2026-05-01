'use strict';

const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class Report extends Model {
  get summary() {
    return {
      critical: this.criticalCount,
      high: this.highCount,
      medium: this.mediumCount,
      low: this.lowCount,
      info: this.infoCount,
      total: this.totalFindings,
    };
  }
}

Report.init(
  {
    id: {
      type: DataTypes.INTEGER.UNSIGNED,
      autoIncrement: true,
      primaryKey: true,
    },
    scanId: {
      type: DataTypes.STRING(36),
      allowNull: false,
      unique: 'idx_reports_scanId',
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
    pullRequestId: {
      type: DataTypes.INTEGER.UNSIGNED,
      allowNull: false,
    },
    pullRequestTitle: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    criticalCount: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    highCount: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    mediumCount: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    lowCount: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    infoCount: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    totalFindings: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    riskScore: {
      type: DataTypes.TINYINT.UNSIGNED,
      defaultValue: 0,
    },
    riskLevel: {
      type: DataTypes.ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'),
      defaultValue: 'NONE',
    },
    findings: {
      type: DataTypes.JSON,
      allowNull: false,
      defaultValue: [],
    },
    npmAuditResult: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: null,
    },
    filesScanned: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    linesScanned: {
      type: DataTypes.INTEGER.UNSIGNED,
      defaultValue: 0,
    },
    scannedAt: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW,
    },
  },
  {
    sequelize,
    modelName: 'Report',
    tableName: 'reports',
    indexes: [
      { fields: ['scanId'] },
      { fields: ['userId', 'riskLevel'] },
      { fields: ['userId', 'createdAt'] },
    ],
    hooks: {
      beforeCreate: computeRisk,
      beforeUpdate: computeRisk,
    },
  }
);

function computeRisk(report) {
  const c = report.criticalCount || 0;
  const h = report.highCount || 0;
  const m = report.mediumCount || 0;
  const l = report.lowCount || 0;
  const i = report.infoCount || 0;

  report.totalFindings = c + h + m + l + i;
  report.riskScore = Math.min(100, Math.round(c * 40 + h * 20 + m * 8 + l * 2 + i * 0.5));

  if (c > 0) report.riskLevel = 'CRITICAL';
  else if (h > 0) report.riskLevel = 'HIGH';
  else if (m > 0) report.riskLevel = 'MEDIUM';
  else if (l > 0) report.riskLevel = 'LOW';
  else report.riskLevel = 'NONE';
}

module.exports = Report;
