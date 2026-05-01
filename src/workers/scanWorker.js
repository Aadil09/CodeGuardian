'use strict';

require('dotenv').config();

const { Worker } = require('bullmq');
const { getRedisConnection } = require('../config/queue');
const { connectDatabase } = require('../config/database');
const { executeScan } = require('../services/scannerService');
const logger = require('../utils/logger');

const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS || '3');
const TIMEOUT_MS = parseInt(process.env.SCAN_TIMEOUT_MS || '300000');

async function startWorker() {
  await connectDatabase();
  const connection = getRedisConnection();

  const worker = new Worker(
    'scan-queue',
    async (job) => {
      logger.info(`Processing scan job ${job.id}`, { scanId: job.data.scanId });
      return executeScan(job.data);
    },
    {
      connection,
      concurrency: MAX_CONCURRENT,
      lockDuration: TIMEOUT_MS,
      stalledInterval: 30000,
      maxStalledCount: 2,
    }
  );

  worker.on('active', (job) => {
    logger.info(`Scan job ${job.id} started`);
  });

  worker.on('completed', (job, result) => {
    logger.info(`Scan job ${job.id} completed`, {
      findings: result?.summary?.total || 0,
    });
  });

  worker.on('failed', (job, err) => {
    logger.error(`Scan job ${job?.id} failed: ${err.message}`);
  });

  worker.on('error', (err) => {
    logger.error('Worker error:', err);
  });

  process.on('SIGTERM', async () => {
    logger.info('Worker shutting down...');
    await worker.close();
    process.exit(0);
  });

  logger.info(`Scan worker started (concurrency: ${MAX_CONCURRENT})`);
}

startWorker().catch((err) => {
  logger.error('Failed to start worker:', err);
  process.exit(1);
});
