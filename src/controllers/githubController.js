'use strict';

const Joi = require('joi');
const githubService = require('../services/githubService');

async function validateConnection(req, res, next) {
  try {
    const schema = Joi.object({
      token: Joi.string().optional(),
      githubUrl: Joi.string().uri().optional(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const token = value.token || req.user.githubToken;
    const githubUrl = value.githubUrl || req.user.githubUrl;

    if (!token) return res.status(400).json({ success: false, message: 'GitHub token required' });

    const result = await githubService.validateToken(token, githubUrl);
    res.json({ success: result.valid, data: result });
  } catch (err) {
    next(err);
  }
}

async function getRepositories(req, res, next) {
  try {
    const schema = Joi.object({
      page: Joi.number().integer().min(1).default(1),
      perPage: Joi.number().integer().min(1).max(100).default(20),
      search: Joi.string().optional().allow(''),
    });
    const { error, value } = schema.validate(req.query);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const token = req.user.githubToken;
    if (!token) return res.status(400).json({ success: false, message: 'GitHub token not configured' });

    const data = await githubService.getRepositories(token, req.user.githubUrl, value);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
}

async function getPullRequests(req, res, next) {
  try {
    const { projectId } = req.params;
    const schema = Joi.object({
      state: Joi.string().valid('opened', 'closed', 'merged', 'all').default('opened'),
      page: Joi.number().integer().min(1).default(1),
      perPage: Joi.number().integer().min(1).max(100).default(20),
    });
    const { error, value } = schema.validate(req.query);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const token = req.user.githubToken;
    if (!token) return res.status(400).json({ success: false, message: 'GitHub token not configured' });

    const data = await githubService.getPullRequests(token, req.user.githubUrl, projectId, value);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
}

async function getPullRequestDetails(req, res, next) {
  try {
    const { projectId, prNumber } = req.params;
    const token = req.user.githubToken;
    if (!token) return res.status(400).json({ success: false, message: 'GitHub token not configured' });

    const data = await githubService.getPullRequestDetails(token, req.user.githubUrl, projectId, prNumber);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
}

module.exports = { validateConnection, getRepositories, getPullRequests, getPullRequestDetails };
