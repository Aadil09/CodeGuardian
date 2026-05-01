'use strict';

const Joi = require('joi');
const authService = require('../services/authService');

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  full_name: Joi.string().min(2).max(100).required(),
  // legacy alias kept for backward compat
  name: Joi.string().min(2).max(100).optional(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

async function register(req, res, next) {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const { user, token } = await authService.register(value);
    res.status(201).json({ success: true, data: { user, token } });
  } catch (err) {
    next(err);
  }
}

async function login(req, res, next) {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const { user, token } = await authService.login(value.email, value.password);
    res.json({ success: true, data: { user, token } });
  } catch (err) {
    next(err);
  }
}

async function externalLogin(req, res, next) {
  try {
    const schema = Joi.object({
      url: Joi.string().uri().required(),
      username: Joi.string().required(),
      password: Joi.string().required(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const result = await authService.loginToExternalSite(value.url, value.username, value.password);
    res.json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
}

async function sendOtp(req, res, next) {
  try {
    const schema = Joi.object({ email: Joi.string().email().required() });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const result = await authService.sendOtp(value.email);
    res.json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
}

async function verifyOtp(req, res, next) {
  try {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      otp: Joi.string().length(6).pattern(/^\d+$/).required(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const result = await authService.verifyOtp(value.email, value.otp);
    res.json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
}

async function resetPassword(req, res, next) {
  try {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      otp: Joi.string().length(6).pattern(/^\d+$/).required(),
      newPassword: Joi.string().min(8).required(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const result = await authService.resetPassword(value.email, value.otp, value.newPassword);
    res.json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
}

async function updateProfile(req, res, next) {
  try {
    const schema = Joi.object({
      full_name: Joi.string().min(2).max(100).optional(),
      email: Joi.string().email().optional(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const result = await authService.updateProfile(req.user.id, value);
    res.json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
}

async function changePassword(req, res, next) {
  try {
    const schema = Joi.object({
      oldPassword: Joi.string().required(),
      newPassword: Joi.string().min(8).required(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const result = await authService.changePassword(req.user.id, value.oldPassword, value.newPassword);
    res.json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
}

async function updateGithubToken(req, res, next) {
  try {
    const schema = Joi.object({
      token: Joi.string().required(),
      githubUrl: Joi.string().uri().optional(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const user = await authService.updateGithubToken(req.user.id, value.token, value.githubUrl);
    res.json({ success: true, data: { user, message: 'GitHub token updated' } });
  } catch (err) {
    next(err);
  }
}

async function getProfile(req, res, next) {
  try {
    const user = await authService.getCurrentUser(req.user.id);
    res.json({ success: true, data: { user } });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  register,
  login,
  externalLogin,
  sendOtp,
  verifyOtp,
  resetPassword,
  updateProfile,
  changePassword,
  updateGithubToken,
  getProfile,
};
