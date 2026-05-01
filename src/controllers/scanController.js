'use strict';

const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');
const { Op } = require('sequelize');
const { Scan } = require('../models');
const { enqueueScan, getScanStatus, cancelScan } = require('../services/scannerService');
const { getPullRequestDetails, getProjectInfo } = require('../services/githubService');
const { createError } = require('../middleware/errorHandler');
const { getPlanFeatureValue } = require('../services/subscriptionService');

const startScanSchema = Joi.object({
  projectId: Joi.alternatives().try(Joi.string(), Joi.number()).required(),
  pullRequestNumber: Joi.number().integer().required(),
  githubUrl: Joi.string().uri().optional(),
});

async function startScan(req, res, next) {
  try {
    const { error, value } = startScanSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const token = req.user.githubToken;
    if (!token) return res.status(400).json({ success: false, message: 'GitHub token not configured. Connect GitHub first.' });

    const githubUrl = value.githubUrl || req.user.githubUrl;
    const projectId = String(value.projectId);

    const [mrDetails, project] = await Promise.all([
      getPullRequestDetails(token, githubUrl, projectId, value.pullRequestNumber),
      getProjectInfo(token, githubUrl, projectId),
    ]);

    const existingActiveScan = await Scan.findOne({
      where: {
        userId: req.user.id,
        projectId,
        pullRequestId: value.pullRequestNumber,
        status: { [Op.in]: ['pending', 'queued', 'running'] },
      },
    });

    if (existingActiveScan) {
      return res.status(409).json({
        success: false,
        message: 'A scan is already in progress for this pull request',
        data: { scanId: existingActiveScan.scanId },
      });
    }

    const scanId = uuidv4();
    const scan = await Scan.create({
      scanId,
      userId: req.user.id,
      projectId,
      projectName: project.nameWithNamespace,
      projectUrl: project.webUrl,
      pullRequestId: mrDetails.iid,
      pullRequestTitle: mrDetails.title,
      pullRequestUrl: mrDetails.webUrl,
      sourceBranch: mrDetails.sourceBranch,
      targetBranch: mrDetails.targetBranch,
      commitSha: mrDetails.sha,
      status: 'queued',
      startedAt: new Date(),
    });

    // Fetch plan-based config; fall back to Basic defaults on any error
    const [hasPriority, scanType] = await Promise.all([
      getPlanFeatureValue(req.user.id, 'priority_processing').catch(() => false),
      getPlanFeatureValue(req.user.id, 'security_scan_type').catch(() => 'basic'),
    ]);

    // Gold/Silver (priority_processing=true) → queue priority 1; Basic → 10
    const queuePriority = hasPriority === true ? 1 : 10;

    const jobId = await enqueueScan({
      scanId,
      projectId,
      projectName: project.nameWithNamespace,
      projectUrl: project.httpUrlToRepo,
      pullRequestId: mrDetails.iid,
      pullRequestTitle: mrDetails.title,
      userId: req.user.id,
      token,
      githubUrl,
      sourceBranch: mrDetails.sourceBranch,
      scanType: scanType ?? 'basic',
    }, { priority: queuePriority });

    await Scan.update({ jobId }, { where: { scanId } });

    res.status(202).json({
      success: true,
      message: 'Scan queued successfully',
      data: { scanId, jobId, status: 'queued' },
    });
  } catch (err) {
    next(err);
  }
}

async function getScanStatusController(req, res, next) {
  try {
    const { scanId } = req.params;
    const scan = await getScanStatus(scanId);
    if (!scan) throw createError('Scan not found', 404);
    if (scan.userId !== req.user.id) throw createError('Forbidden', 403);
    res.json({ success: true, data: scan });
  } catch (err) {
    next(err);
  }
}

async function listScans(req, res, next) {
  try {
    const schema = Joi.object({
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(20),
      status: Joi.string().valid('pending', 'queued', 'running', 'completed', 'failed', 'cancelled').optional(),
      projectId: Joi.string().optional(),
    });
    const { error, value } = schema.validate(req.query);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const where = { userId: req.user.id };
    if (value.status) where.status = value.status;
    if (value.projectId) where.projectId = value.projectId;

    const { count: total, rows: scans } = await Scan.findAndCountAll({
      where,
      order: [['createdAt', 'DESC']],
      offset: (value.page - 1) * value.limit,
      limit: value.limit,
      raw: true,
    });

    res.json({
      success: true,
      data: {
        scans,
        total,
        page: value.page,
        limit: value.limit,
        totalPages: Math.ceil(total / value.limit),
      },
    });
  } catch (err) {
    next(err);
  }
}

async function cancelScanController(req, res, next) {
  try {
    const { scanId } = req.params;
    const scan = await Scan.findOne({ where: { scanId, userId: req.user.id } });
    if (!scan) throw createError('Scan not found', 404);
    if (!['pending', 'queued', 'running'].includes(scan.status)) {
      return res.status(400).json({ success: false, message: 'Scan cannot be cancelled in its current state' });
    }
    const updated = await cancelScan(scanId);
    res.json({ success: true, data: updated });
  } catch (err) {
    next(err);
  }
}

module.exports = { startScan, getScanStatusController, listScans, cancelScanController };
