'use strict';

require('dotenv').config();

const express = require('express');
const serverless = require('serverless-http');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const { connectDatabase } = require('./src/config/database');
const errorHandler = require('./src/middleware/errorHandler');
const { globalLimiter } = require('./src/middleware/rateLimiter');
const logger = require('./src/utils/logger');

const authRoutes         = require('./src/routes/auth');
const githubRoutes       = require('./src/routes/github');
const scanRoutes         = require('./src/routes/scan');
const reportRoutes       = require('./src/routes/report');
const subscriptionRoutes = require('./src/routes/subscription');

const app = express();

let isInitialized = false;

async function init() {
  if (!isInitialized) {
    await connectDatabase();
    if (process.env.REDIS_HOST && process.env.REDIS_HOST !== 'localhost') {
      const { initQueue } = require('./src/config/queue');
      await initQueue();
    } else {
      logger.warn('Redis not configured — queue disabled (serverless mode)');
    }
    isInitialized = true;
    logger.info('Serverless init done');
  }
}

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(globalLimiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined', {
  stream: { write: (msg) => logger.info(msg.trim()) }
}));

app.use('/api/auth',         authRoutes);
app.use('/api/github',       githubRoutes);
app.use('/api/scan',         scanRoutes);
app.use('/api/report',       reportRoutes);
app.use('/api/subscription', subscriptionRoutes);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.use(errorHandler);

module.exports = async (req, res) => {
  await init();
  return serverless(app)(req, res);
};

