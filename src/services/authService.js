'use strict';

const jwt = require('jsonwebtoken');
const puppeteer = require('puppeteer');
const { User, Otp } = require('../models');
const logger = require('../utils/logger');
const { createError } = require('../middleware/errorHandler');
const { assignBasicPlan } = require('./subscriptionService');

function generateToken(userId) {
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '24h', algorithm: 'HS256' }
  );
}

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function register(data) {
  const { email, password, full_name, name } = data;
  const displayName = full_name || name;

  // Manual duplicate check — no unique constraint relied upon
  const existing = await User.findOne({
    where: { email: email.toLowerCase(), isDeleted: false },
  });
  if (existing) throw createError('Email already registered', 409);

  const user = await User.create({ email, password, name: displayName });

  // Auto-assign Basic (free) plan — fire-and-forget; don't fail registration if seeder hasn't run yet
  assignBasicPlan(user.id).catch(err =>
    logger.warn(`Could not assign Basic plan to user ${user.id}: ${err.message}`)
  );

  const token = generateToken(user.id);
  return { user: user.toPublic(), token };
}

async function login(email, password) {
  logger.info(`Login attempt for email: ${email}`);
  const user = await User.findOne({
    where: { email: email.toLowerCase(), isActive: true, isDeleted: false },
  });
  if (!user) throw createError('Invalid email or password', 401);

  const isMatch = await user.comparePassword(password);
  if (!isMatch) throw createError('Invalid email or password', 401);

  user.lastLogin = new Date();
  await user.save();

  const token = generateToken(user.id);
  const userData = user.toPublic();
  userData.githubToken = user.githubToken || null;
  return { user: userData, token };
}

async function sendOtp(email) {
  const user = await User.findOne({
    where: { email: email.toLowerCase(), isActive: true, isDeleted: false },
  });
  if (!user) throw createError('No account found with this email', 404);

  // Invalidate all previous OTPs for this email
  await Otp.update({ isUsed: true }, { where: { email: email.toLowerCase() } });

  // const otp = generateOtp();
  const otp = 123456; // For testing purposes, use a fixed OTP
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

  await Otp.create({ email: email.toLowerCase(), otp, expiresAt });

  // Simulate email delivery
  logger.info(`[OTP EMAIL] To: ${email} | OTP: ${otp} | Expires: ${expiresAt.toISOString()}`);

  return { message: 'OTP sent to your email address' };
}

async function verifyOtp(email, otp) {
  const record = await Otp.findOne({
    where: { email: email.toLowerCase(), otp, isUsed: false },
  });

  if (!record) throw createError('Invalid OTP', 400);
  if (record.isExpired()) throw createError('OTP has expired. Please request a new one.', 400);

  return { valid: true, message: 'OTP verified successfully' };
}

async function resetPassword(email, otp, newPassword) {
  const record = await Otp.findOne({
    where: { email: email.toLowerCase(), otp, isUsed: false },
  });

  if (!record) throw createError('Invalid or already used OTP', 400);
  if (record.isExpired()) throw createError('OTP has expired. Please request a new one.', 400);

  const user = await User.findOne({
    where: { email: email.toLowerCase(), isDeleted: false },
  });
  if (!user) throw createError('User not found', 404);

  user.password = newPassword; // hashed by beforeUpdate hook
  await user.save();

  record.isUsed = true;
  await record.save();

  return { message: 'Password reset successfully. Please log in.' };
}

async function updateProfile(userId, data) {
  const user = await User.findOne({ where: { id: userId, isDeleted: false } });
  if (!user) throw createError('User not found', 404);

  if (data.email && data.email.toLowerCase() !== user.email) {
    const duplicate = await User.findOne({
      where: { email: data.email.toLowerCase(), isDeleted: false },
    });
    if (duplicate) throw createError('Email already in use by another account', 409);
    user.email = data.email;
  }

  if (data.full_name && data.full_name.trim().length >= 2) {
    user.name = data.full_name.trim();
  }

  await user.save();
  return { user: user.toPublic() };
}

async function changePassword(userId, oldPassword, newPassword) {
  const user = await User.findOne({ where: { id: userId, isDeleted: false } });
  if (!user) throw createError('User not found', 404);

  const isMatch = await user.comparePassword(oldPassword);
  if (!isMatch) throw createError('Current password is incorrect', 400);

  user.password = newPassword; // hashed by beforeUpdate hook
  await user.save();

  return { message: 'Password changed successfully' };
}

async function loginToExternalSite(url, username, password) {
  let browser;
  try {
    logger.info(`Starting Puppeteer login to ${url}`);
    browser = await puppeteer.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
      ],
    });

    const page = await browser.newPage();
    await page.setDefaultNavigationTimeout(30000);
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    await page.goto(url, { waitUntil: 'networkidle2' });

    const usernameSelector = await findInputSelector(page, ['username', 'email', 'user', 'login']);
    const passwordSelector = await findInputSelector(page, ['password', 'pass', 'pwd']);

    if (!usernameSelector || !passwordSelector) {
      throw new Error('Could not locate login form fields');
    }

    await page.type(usernameSelector, username, { delay: 50 });
    await page.type(passwordSelector, password, { delay: 50 });

    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }),
      page.keyboard.press('Enter'),
    ]);

    const cookies = await page.cookies();
    const sessionCookie = cookies.map(c => `${c.name}=${c.value}`).join('; ');
    const currentUrl = page.url();

    const loginFailed =
      currentUrl === url ||
      (await page.$('.error, .alert-danger, .login-error')) !== null;

    if (loginFailed) throw new Error('Login failed — invalid credentials or unexpected page state');

    logger.info('External site login successful');
    return { success: true, sessionCookie, cookies, currentUrl };
  } catch (err) {
    logger.error('External login failed:', err.message);
    throw createError(`External login failed: ${err.message}`, 502);
  } finally {
    if (browser) await browser.close();
  }
}

async function findInputSelector(page, keywords) {
  for (const keyword of keywords) {
    const selector = `input[name*="${keyword}"], input[id*="${keyword}"], input[placeholder*="${keyword}"]`;
    const el = await page.$(selector);
    if (el) return selector;
  }
  return null;
}

async function updateGithubToken(userId, token, githubUrl) {
  const user = await User.findByPk(userId);
  if (!user) throw createError('User not found', 404);
  user.githubToken = token;
  if (githubUrl) user.githubUrl = githubUrl;
  await user.save();
  return user.toPublic();
}

async function getCurrentUser(userId) {
  const user = await User.findOne({ where: { id: userId, isDeleted: false } });
  if (!user) throw createError('User not found', 404);
  const data = user.toPublic();
  data.githubToken = user.githubToken || null;
  return data;
}

module.exports = {
  register,
  login,
  sendOtp,
  verifyOtp,
  resetPassword,
  updateProfile,
  changePassword,
  loginToExternalSite,
  updateGithubToken,
  getCurrentUser,
  generateToken,
};
