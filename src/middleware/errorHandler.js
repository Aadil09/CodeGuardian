'use strict';

const logger = require('../utils/logger');

function errorHandler(err, req, res, _next) {
  // Sequelize: unique constraint (duplicate email, etc.)
  if (err.name === 'SequelizeUniqueConstraintError') {
    const field = err.errors?.[0]?.path || 'field';
    logger.warn(`Duplicate ${field}: ${req.method} ${req.path}`);
    return res.status(409).json({ success: false, message: `${field} already exists` });
  }

  // Sequelize: model validation errors
  if (err.name === 'SequelizeValidationError') {
    const messages = err.errors.map(e => e.message);
    logger.warn(`Validation error: ${req.method} ${req.path} — ${messages.join(', ')}`);
    return res.status(400).json({ success: false, message: 'Validation failed', errors: messages });
  }

  // Sequelize: DB-level errors (bad query, wrong type, etc.)
  if (err.name === 'SequelizeDatabaseError') {
    logger.error('Database error:', { message: err.message, path: req.path, method: req.method });
    return res.status(500).json({ success: false, message: 'Database error' });
  }

  // Sequelize: connection errors
  if (err.name === 'SequelizeConnectionError' || err.name === 'SequelizeConnectionRefusedError') {
    logger.error('Database connection error:', { message: err.message });
    return res.status(503).json({ success: false, message: 'Service temporarily unavailable' });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }

  // Application errors thrown via createError() with a statusCode
  if (err.statusCode) {
    const level = err.statusCode >= 500 ? 'error' : 'warn';
    logger[level](`${err.statusCode} ${err.message}`, { path: req.path, method: req.method });
    return res.status(err.statusCode).json({ success: false, message: err.message });
  }

  // Unexpected errors — always log as error with stack
  logger.error('Unhandled error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  res.status(500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
  });
}

function createError(message, statusCode = 500) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

module.exports = errorHandler;
module.exports.createError = createError;
