'use strict';

const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const githubController = require('../controllers/githubController');

router.use(authenticate);
router.post('/connect', githubController.validateConnection);
router.get('/repos', githubController.getRepositories);
router.get('/repos/:projectId/pulls', githubController.getPullRequests);
router.get('/repos/:projectId/pulls/:prNumber', githubController.getPullRequestDetails);

module.exports = router;
