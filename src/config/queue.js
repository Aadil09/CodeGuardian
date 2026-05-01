'use strict';

const { Queue, Worker, QueueEvents } = require('bullmq');
const IORedis = require('ioredis');
const logger = require('../utils/logger');

let connection;
let scanQueue;
let queueEvents;

function getRedisConnection() {
  if (!connection) {
    connection = new IORedis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD || undefined,
      maxRetriesPerRequest: null,
      enableReadyCheck: false,
      showFriendlyErrorStack: false,
    });
    // suppress the "recommended Redis 6.2+" advisory — Redis 6.0 works fine
    const originalWarn = console.warn.bind(console);
    console.warn = (...args) => {
      if (typeof args[0] === 'string' && args[0].includes('minimum Redis version')) return;
      originalWarn(...args);
    };

    connection.on('error', (err) => logger.error('Redis connection error:', err));
    connection.on('connect', () => logger.info('Redis connected'));
  }
  return connection;
}

async function initQueue() {
  const conn = getRedisConnection();

  scanQueue = new Queue('scan-queue', {
    connection: conn,
    defaultJobOptions: {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
      removeOnComplete: { count: 100 },
      removeOnFail: { count: 50 },
    },
  });

  queueEvents = new QueueEvents('scan-queue', { connection: conn });

  queueEvents.on('completed', ({ jobId }) => logger.info(`Scan job ${jobId} completed`));
  queueEvents.on('failed', ({ jobId, failedReason }) =>
    logger.error(`Scan job ${jobId} failed: ${failedReason}`)
  );

  logger.info('BullMQ scan queue initialized');
  return scanQueue;
}

function getScanQueue() {
  if (!scanQueue) throw new Error('Queue not initialized. Call initQueue() first.');
  return scanQueue;
}

module.exports = { initQueue, getScanQueue, getRedisConnection };
