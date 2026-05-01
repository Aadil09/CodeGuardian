'use strict';

const { Sequelize } = require('sequelize');
const logger = require('../utils/logger');

const sequelize = new Sequelize(
  process.env.DB_NAME || 'security_scanner',
  process.env.DB_USER || 'root',
  process.env.DB_PASSWORD || '',
  {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306'),
    dialect: 'mysql',
    logging: (sql) => logger.debug(sql),
    pool: {
      max: 10,
      min: 2,
      acquire: 30000,
      idle: 10000,
    },
    define: {
      underscored: false,
      timestamps: true,
    },
  }
);

async function connectDatabase() {
  await sequelize.authenticate();
  logger.info('MySQL connected via Sequelize');

  try {
    // Import all models
    require('../models');
    
    // PRODUCTION SAFE: No automatic sync
    // Tables must exist already or be created manually
    // This prevents ghost constraint errors and data loss
    if (process.env.DB_AUTO_SYNC === 'true') {
      logger.warn('DB_AUTO_SYNC is enabled - use only in development!');
      await sequelize.sync({ alter: true });
      logger.info('Database tables synced (alter mode)');
    } else {
      logger.info('Database sync skipped (production mode)');
    }

    // Seed plans & features
    const { seedSubscriptions } = require('../seeders/subscriptionSeeder');
    await seedSubscriptions();
  } catch (err) {
    logger.error('Database initialization failed:', err);
    throw err;
  }


}

module.exports = { sequelize, connectDatabase };
