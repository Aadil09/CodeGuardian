-- ============================================================================
-- GitLab Security Scanner - Subscription Tables Migration
-- Run this manually: mysql -u root -p security_scanner < create_subscription_tables.sql
-- ============================================================================

-- Drop existing subscription tables (safe - won't touch users/scans/reports)
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS usage_tracking;
DROP TABLE IF EXISTS user_subscriptions;
DROP TABLE IF EXISTS plan_features;
DROP TABLE IF EXISTS features;
DROP TABLE IF EXISTS plans;
SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================================
-- Plans Table
-- ============================================================================
CREATE TABLE plans (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  slug VARCHAR(50) NOT NULL UNIQUE,
  description TEXT,
  price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
  billingCycle VARCHAR(20) NOT NULL DEFAULT 'monthly',
  isActive TINYINT(1) NOT NULL DEFAULT 1,
  sortOrder INT NOT NULL DEFAULT 0,
  metadata JSON,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_slug (slug),
  INDEX idx_active (isActive)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Features Table
-- ============================================================================
CREATE TABLE features (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `key` VARCHAR(100) NOT NULL UNIQUE,
  name VARCHAR(200) NOT NULL,
  description TEXT,
  type ENUM('limit', 'boolean', 'enum') NOT NULL DEFAULT 'limit',
  unit VARCHAR(50),
  isActive TINYINT(1) NOT NULL DEFAULT 1,
  sortOrder INT NOT NULL DEFAULT 0,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_key (`key`),
  INDEX idx_active (isActive)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Plan Features (Junction Table)
-- ============================================================================
CREATE TABLE plan_features (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  planId INT UNSIGNED NOT NULL,
  featureId INT UNSIGNED NOT NULL,
  value VARCHAR(255) NOT NULL,
  isEnabled TINYINT(1) NOT NULL DEFAULT 1,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (planId) REFERENCES plans(id) ON DELETE CASCADE,
  FOREIGN KEY (featureId) REFERENCES features(id) ON DELETE CASCADE,
  UNIQUE KEY unique_plan_feature (planId, featureId),
  INDEX idx_plan (planId),
  INDEX idx_feature (featureId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- User Subscriptions
-- ============================================================================
CREATE TABLE user_subscriptions (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  userId INT UNSIGNED NOT NULL,
  planId INT UNSIGNED NOT NULL,
  status ENUM('active', 'cancelled', 'expired', 'pending') NOT NULL DEFAULT 'active',
  startedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expiresAt DATETIME,
  cancelledAt DATETIME,
  previousPlanId INT UNSIGNED,
  metadata JSON,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (planId) REFERENCES plans(id) ON DELETE RESTRICT,
  INDEX idx_user_status (userId, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Usage Tracking
-- ============================================================================
CREATE TABLE usage_tracking (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  userId INT UNSIGNED NOT NULL,
  featureId INT UNSIGNED NOT NULL,
  usedCount INT NOT NULL DEFAULT 0,
  periodStart DATE NOT NULL,
  periodEnd DATE NOT NULL,
  metadata JSON,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (featureId) REFERENCES features(id) ON DELETE CASCADE,
  UNIQUE KEY unique_user_feature_period (userId, featureId, periodStart),
  INDEX idx_user_period (userId, periodStart, periodEnd)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Done!
-- ============================================================================
SELECT 'Subscription tables created successfully!' AS status;
