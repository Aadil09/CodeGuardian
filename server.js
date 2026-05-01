'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { connectDatabase } = require('./src/config/database');
const { initQueue } = require('./src/config/queue');
const errorHandler = require('./src/middleware/errorHandler');
const { globalLimiter } = require('./src/middleware/rateLimiter');
const logger = require('./src/utils/logger');

const authRoutes         = require('./src/routes/auth');
const githubRoutes       = require('./src/routes/github');
const scanRoutes         = require('./src/routes/scan');
const reportRoutes       = require('./src/routes/report');
const subscriptionRoutes = require('./src/routes/subscription');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:4200',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(globalLimiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(morgan('combined', {
  stream: { write: (msg) => logger.info(msg.trim()) }
}));

app.use('/api/auth',         authRoutes);
app.use('/api/github',       githubRoutes);
app.use('/api/scan',         scanRoutes);
app.use('/api/report',       reportRoutes);
app.use('/api/subscription', subscriptionRoutes);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), version: '1.0.0' });
});

app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.use(errorHandler);

async function bootstrap() {
  try {
    await connectDatabase();
    await initQueue();
    const server = app.listen(PORT, () => {
      logger.info(`Security Scanner API running on port ${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        logger.error(`Port ${PORT} is already in use. Kill the existing process first: lsof -ti:${PORT} | xargs kill -9`);
      } else {
        logger.error('Server error:', err.message);
      }
      process.exit(1);
    });
  } catch (err) {
    logger.error('Failed to start server:', err.message);
    process.exit(1);
  }
}

bootstrap();

module.exports = app;
