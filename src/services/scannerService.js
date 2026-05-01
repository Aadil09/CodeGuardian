'use strict';

const { exec } = require('child_process');
const { promisify } = require('util');
const path = require('path');
const { Op } = require('sequelize');
const logger = require('../utils/logger');
const { Scan, Report } = require('../models');
const { scanDirectory, computeSummary } = require('../scanner/owaspScanner');
const { runESLint } = require('../scanner/eslintScanner');
const { cloneRepository, fetchChangedFiles } = require('./githubService');
const { ensureDirectoryExists, deleteDirRecursive } = require('../utils/helpers');
const { getScanQueue } = require('../config/queue');
const { getPlanFeatureValue } = require('./subscriptionService');

const execAsync = promisify(exec);

// priority: 1 = highest (Gold), 5 = Silver, 10 = Basic (lowest)
async function enqueueScan(scanData, { priority = 10 } = {}) {
  const queue = getScanQueue();
  const job = await queue.add('scan', scanData, {
    jobId: scanData.scanId,
    priority,
  });
  return job.id;
}

async function executeScan(scanData) {
  const {
    scanId, projectId, pullRequestId, userId, token,
    githubUrl, projectUrl, sourceBranch, projectName, pullRequestTitle,
    scanType = 'basic',
  } = scanData;

  const scan = await Scan.findOne({ where: { scanId } });
  if (!scan) throw new Error(`Scan ${scanId} not found`);

  const cloneDir = process.env.CLONE_DIR || '/tmp/security-scanner-repos';
  ensureDirectoryExists(cloneDir);
  let repoDir;

  try {
    await updateScanStatus(scanId, 'running', 5);

    repoDir = await cloneRepository(token, projectUrl, cloneDir, sourceBranch);

    await updateScanStatus(scanId, 'running', 20);

    const { findings, filesScanned, linesScanned } = await scanDirectory(repoDir, async ({ progress }) => {
      await updateScanStatus(scanId, 'running', 20 + Math.round(progress * 0.5));
    });

    await updateScanStatus(scanId, 'running', 72);

    // Enforce lines_of_code_limit — checked after scanning since we need the actual count
    const linesLimit = await getPlanFeatureValue(userId, 'lines_of_code_limit').catch(() => null);
    if (linesLimit !== null && linesLimit !== -1 && linesScanned > linesLimit) {
      throw new Error(
        `PR exceeds your plan's line limit: ${linesScanned.toLocaleString()} lines scanned, ` +
        `limit is ${linesLimit.toLocaleString()}. Upgrade your plan to scan larger codebases.`
      );
    }

    // ESLint + npm audit are advanced-only features
    let eslintFindings = [];
    let npmAuditResult = null;

    if (scanType === 'advanced') {
      const changedFiles = await fetchChangedFiles(token, githubUrl, projectId, pullRequestId).catch(() => []);
      eslintFindings = await runESLint(
        changedFiles.length > 0 ? changedFiles.map(f => f.path) : [],
        repoDir
      ).catch(() => []);

      await updateScanStatus(scanId, 'running', 85);

      npmAuditResult = await runNpmAudit(repoDir);
    }

    await updateScanStatus(scanId, 'running', 95);

    const allFindings = [...findings, ...eslintFindings];
    const summary = computeSummary(allFindings);

    const report = await Report.create({
      scanId,
      userId,
      projectId,
      projectName,
      pullRequestId,
      pullRequestTitle,
      criticalCount: summary.critical,
      highCount: summary.high,
      mediumCount: summary.medium,
      lowCount: summary.low,
      infoCount: summary.info,
      findings: allFindings,
      npmAuditResult,
      filesScanned,
      linesScanned,
      scannedAt: new Date(),
    });

    await Scan.update(
      {
        status: 'completed',
        progress: 100,
        completedAt: new Date(),
        durationMs: Date.now() - new Date(scan.startedAt).getTime(),
        filesScanned,
        linesScanned,
      },
      { where: { scanId } }
    );

    logger.info(`Scan ${scanId} completed [${scanType}]: ${allFindings.length} findings`);
    return report;

  } catch (err) {
    await Scan.update(
      { status: 'failed', errorMessage: err.message, completedAt: new Date() },
      { where: { scanId } }
    );
    logger.error(`Scan ${scanId} failed: ${err.message}`);
    throw err;
  } finally {
    if (repoDir) {
      deleteDirRecursive(repoDir);
      logger.info(`Cleaned up repo dir: ${repoDir}`);
    }
  }
}

async function runNpmAudit(repoDir) {
  const fs = require('fs');
  if (!fs.existsSync(path.join(repoDir, 'package.json'))) return null;
  try {
    const { stdout } = await execAsync('npm audit --json', { cwd: repoDir, timeout: 60000 });
    return JSON.parse(stdout);
  } catch (err) {
    if (err.stdout) {
      try { return JSON.parse(err.stdout); } catch (_) {}
    }
    logger.warn(`npm audit failed in ${repoDir}: ${err.message}`);
    return null;
  }
}

async function updateScanStatus(scanId, status, progress) {
  await Scan.update({ status, progress }, { where: { scanId } });
  logger.debug(`Scan ${scanId}: [${progress}%] ${status}`);
}

async function getScanStatus(scanId) {
  const scan = await Scan.findOne({ where: { scanId }, raw: true });
  return scan;
}

async function cancelScan(scanId) {
  const queue = getScanQueue();
  const job = await queue.getJob(scanId);
  if (job) await job.remove();
  await Scan.update({ status: 'cancelled' }, { where: { scanId } });
  return Scan.findOne({ where: { scanId }, raw: true });
}

module.exports = { enqueueScan, executeScan, getScanStatus, cancelScan, runNpmAudit };
