'use strict';

const Joi = require('joi');
const reportService = require('../services/reportService');
const { createError } = require('../middleware/errorHandler');

async function getReports(req, res, next) {
  try {
    const schema = Joi.object({
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(20),
      projectId: Joi.string().optional(),
      riskLevel: Joi.string().valid('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE').optional(),
    });
    const { error, value } = schema.validate(req.query);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const data = await reportService.getReports(req.user.id, value);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
}

async function getReport(req, res, next) {
  try {
    const { scanId } = req.params;
    const report = await reportService.getReportByScanId(scanId, req.user.id);
    res.json({ success: true, data: report });
  } catch (err) {
    next(err);
  }
}

async function getStats(req, res, next) {
  try {
    const data = await reportService.getReportStats(req.user.id);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
}

async function getTopVulnerabilities(req, res, next) {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const data = await reportService.getTopVulnerabilities(req.user.id, limit);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
}

async function deleteReport(req, res, next) {
  try {
    const { scanId } = req.params;
    const data = await reportService.deleteReport(scanId, req.user.id);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
}

async function exportReport(req, res, next) {
  try {
    const { scanId } = req.params;
    const { format = 'json' } = req.query; // json or pdf
    const report = await reportService.getReportByScanId(scanId, req.user.id);

    if (format === 'pdf') {
      const { generateReportPDF } = require('../utils/pdfGenerator');
      const doc = generateReportPDF(report);
      
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="security-report-${scanId}.pdf"`);
      doc.pipe(res);
    } else {
      // JSON export
      const filename = `security-report-${scanId}.json`;
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Type', 'application/json');
      res.json({ success: true, exportedAt: new Date().toISOString(), data: report });
    }
  } catch (err) {
    next(err);
  }
}

module.exports = { getReports, getReport, getStats, getTopVulnerabilities, deleteReport, exportReport };
