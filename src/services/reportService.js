'use strict';

const { Op, fn, col, literal } = require('sequelize');
const { Report } = require('../models');
const { createError } = require('../middleware/errorHandler');
const { groupBy } = require('../utils/helpers');

function parseJson(value, fallback) {
  if (value == null) return fallback;
  if (typeof value === 'string') {
    try { return JSON.parse(value); } catch { return fallback; }
  }
  return value;
}

function toApiReport(report) {
  const plain = report.get ? report.get({ plain: true }) : report;
  return {
    ...plain,
    findings: parseJson(plain.findings, []),
    npmAuditResult: parseJson(plain.npmAuditResult, null),
    summary: {
      critical: plain.criticalCount,
      high: plain.highCount,
      medium: plain.mediumCount,
      low: plain.lowCount,
      info: plain.infoCount,
      total: plain.totalFindings,
    },
  };
}

async function getReports(userId, options = {}) {
  const { page = 1, limit = 20, projectId, riskLevel, sortBy = 'createdAt', order = 'desc' } = options;

  const where = { userId };
  if (projectId) where.projectId = projectId;
  if (riskLevel) where.riskLevel = riskLevel.toUpperCase();

  const { count: total, rows } = await Report.findAndCountAll({
    where,
    attributes: { exclude: ['findings', 'npmAuditResult'] },
    order: [[sortBy, order.toUpperCase()]],
    offset: (page - 1) * limit,
    limit,
    raw: false,
  });

  return {
    reports: rows.map(toApiReport),
    total,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
  };
}

async function getReportByScanId(scanId, userId) {
  const report = await Report.findOne({ where: { scanId, userId } });
  if (!report) throw createError('Report not found', 404);
  return toApiReport(report);
}

async function getReportStats(userId) {
  const [aggRow] = await Report.findAll({
    where: { userId },
    attributes: [
      [fn('COUNT', col('id')), 'totalReports'],
      [fn('SUM', col('totalFindings')), 'totalFindings'],
      [fn('SUM', col('criticalCount')), 'criticalCount'],
      [fn('SUM', col('highCount')), 'highCount'],
      [fn('SUM', col('mediumCount')), 'mediumCount'],
      [fn('SUM', col('lowCount')), 'lowCount'],
      [fn('AVG', col('riskScore')), 'avgRiskScore'],
    ],
    raw: true,
  });

  const riskRows = await Report.findAll({
    where: { userId },
    attributes: ['riskLevel', [fn('COUNT', col('id')), 'count']],
    group: ['riskLevel'],
    raw: true,
  });

  const recentRows = await Report.findAll({
    where: { userId },
    attributes: ['scanId', 'pullRequestTitle', 'projectName', 'riskLevel',
      'criticalCount', 'highCount', 'mediumCount', 'lowCount', 'infoCount', 'totalFindings', 'createdAt'],
    order: [['createdAt', 'DESC']],
    limit: 10,
    raw: true,
  });

  return {
    summary: {
      totalReports: parseInt(aggRow?.totalReports || 0),
      totalFindings: parseInt(aggRow?.totalFindings || 0),
      criticalCount: parseInt(aggRow?.criticalCount || 0),
      highCount: parseInt(aggRow?.highCount || 0),
      mediumCount: parseInt(aggRow?.mediumCount || 0),
      lowCount: parseInt(aggRow?.lowCount || 0),
      avgRiskScore: parseFloat(aggRow?.avgRiskScore || 0).toFixed(1),
    },
    riskDistribution: riskRows.reduce((acc, r) => ({ ...acc, [r.riskLevel]: parseInt(r.count) }), {}),
    recentActivity: recentRows.map(r => ({
      ...r,
      summary: {
        critical: r.criticalCount,
        high: r.highCount,
        medium: r.mediumCount,
        low: r.lowCount,
        info: r.infoCount,
        total: r.totalFindings,
      },
    })),
  };
}

async function getTopVulnerabilities(userId, limit = 10) {
  const reports = await Report.findAll({
    where: { userId },
    attributes: ['findings'],
    raw: true,
  });

  const allFindings = reports.flatMap(r => {
    const f = r.findings;
    return Array.isArray(f) ? f : (typeof f === 'string' ? JSON.parse(f) : []);
  });

  const grouped = groupBy(allFindings, 'ruleId');
  return Object.entries(grouped)
    .map(([ruleId, findings]) => ({
      ruleId,
      ruleName: findings[0].ruleName,
      count: findings.length,
      severity: findings[0].severity,
      category: findings[0].category,
      owasp: findings[0].owasp,
    }))
    .sort((a, b) => {
      const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
      return (order[b.severity] - order[a.severity]) || (b.count - a.count);
    })
    .slice(0, limit);
}

async function deleteReport(scanId, userId) {
  const report = await Report.findOne({ where: { scanId, userId } });
  if (!report) throw createError('Report not found', 404);
  await report.destroy();
  return { success: true };
}

module.exports = { getReports, getReportByScanId, getReportStats, getTopVulnerabilities, deleteReport };
