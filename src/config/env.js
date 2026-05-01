'use strict';

const Joi = require('joi');

const envSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_EXPIRES_IN: Joi.string().default('24h'),
  DB_HOST: Joi.string().default('localhost'),
  DB_PORT: Joi.number().default(3306),
  DB_NAME: Joi.string().required(),
  DB_USER: Joi.string().required(),
  DB_PASSWORD: Joi.string().allow('').default(''),
  REDIS_HOST: Joi.string().default('localhost'),
  REDIS_PORT: Joi.number().default(6379),
  GITHUB_BASE_URL: Joi.string().uri().default('https://api.github.com'),
  GITHUB_TOKEN: Joi.string().required(),
  CLONE_DIR: Joi.string().default('/tmp/security-scanner-repos'),
  MAX_CONCURRENT_SCANS: Joi.number().default(3),
  SCAN_TIMEOUT_MS: Joi.number().default(300000),
  FRONTEND_URL: Joi.string().default('http://localhost:4200'),
}).unknown(true);

const { error, value } = envSchema.validate(process.env);

if (error && process.env.NODE_ENV !== 'test') {
  throw new Error(`Environment validation failed: ${error.message}`);
}

module.exports = value || process.env;
