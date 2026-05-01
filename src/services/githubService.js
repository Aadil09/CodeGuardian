'use strict';

const axios = require('axios');
const simpleGit = require('simple-git');
const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');
const { ensureDirectoryExists, deleteDirRecursive } = require('../utils/helpers');

function createGithubClient(token, baseUrl) {
  return axios.create({
    baseURL: baseUrl || process.env.GITHUB_BASE_URL || 'https://api.github.com',
    headers: {
      'Authorization': `token ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
    },
    timeout: 30000,
  });
}

async function getRepositories(token, baseUrl, options = {}) {
  const client = createGithubClient(token, baseUrl);
  const { page = 1, perPage = 20, search = '' } = options;

  let url = '/user/repos';
  let params = {
    per_page: perPage,
    page,
    sort: 'updated',
    direction: 'desc',
  };

  if (search) {
    url = '/search/repositories';
    params = {
      q: `${search} in:name user:@me`,
      per_page: perPage,
      page,
      sort: 'updated',
      order: 'desc'
    };
  }

  const response = await client.get(url, { params });
  const items = search ? response.data.items : response.data;

  return {
    projects: items.map(mapRepository),
    total: search ? response.data.total_count : items.length,
    totalPages: 1,
    page: parseInt(page),
  };
}

async function getPullRequests(token, baseUrl, projectId, options = {}) {
  const client = createGithubClient(token, baseUrl);
  const { state = 'opened', page = 1, perPage = 20 } = options;

  const ghState = state === 'opened' ? 'open' : (state === 'merged' ? 'closed' : state);

  const response = await client.get(`/repos/${projectId}/pulls`, {
    params: { state: ghState, per_page: perPage, page, sort: 'updated', direction: 'desc' },
  });

  return {
    pullRequests: response.data.map(mapPullRequest),
    total: response.data.length,
    totalPages: 1,
    page: parseInt(page),
  };
}

async function getPullRequestChanges(token, baseUrl, projectId, prNumber) {
  const client = createGithubClient(token, baseUrl);
  const response = await client.get(`/repos/${projectId}/pulls/${prNumber}/files`);
  return response.data;
}

async function getPullRequestDetails(token, baseUrl, projectId, prNumber) {
  const client = createGithubClient(token, baseUrl);
  const response = await client.get(`/repos/${projectId}/pulls/${prNumber}`);
  return mapPullRequest(response.data);
}

async function getProjectInfo(token, baseUrl, projectId) {
  const client = createGithubClient(token, baseUrl);
  const response = await client.get(`/repos/${projectId}`);
  return mapRepository(response.data);
}

async function validateToken(token, baseUrl) {
  try {
    const client = createGithubClient(token, baseUrl);
    const response = await client.get('/user');
    return { valid: true, user: response.data };
  } catch (err) {
    return { valid: false, error: err.response?.data?.message || err.message };
  }
}

async function cloneRepository(token, projectUrl, cloneDir, branch) {
  const repoDir = path.join(cloneDir, `repo_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`);
  ensureDirectoryExists(repoDir);

  const urlWithAuth = projectUrl.replace(
    /^(https?:\/\/)/,
    `$1x-access-token:${token}@`
  );

  try {
    const git = simpleGit();
    logger.info(`Cloning ${projectUrl} into ${repoDir}`);

    await git.clone(urlWithAuth, repoDir, ['--depth', '1', '--single-branch', ...(branch ? ['--branch', branch] : [])]);
    logger.info(`Successfully cloned to ${repoDir}`);
    return repoDir;
  } catch (err) {
    deleteDirRecursive(repoDir);
    throw new Error(`Clone failed: ${err.message}`);
  }
}

async function fetchChangedFiles(token, baseUrl, projectId, prNumber) {
  const files = await getPullRequestChanges(token, baseUrl, projectId, prNumber);
  return files
    .filter(f => f.status !== 'removed')
    .map(f => ({
      path: f.filename,
      oldPath: f.previous_filename || f.filename,
      newFile: f.status === 'added',
      renamedFile: f.status === 'renamed',
      diff: f.patch,
    }));
}

function mapRepository(repo) {
  return {
    id: repo.full_name,
    name: repo.name,
    nameWithNamespace: repo.full_name,
    path: repo.name,
    pathWithNamespace: repo.full_name,
    description: repo.description,
    visibility: repo.private ? 'private' : 'public',
    httpUrlToRepo: repo.clone_url,
    webUrl: repo.html_url,
    defaultBranch: repo.default_branch,
    lastActivityAt: repo.updated_at,
    namespace: { name: repo.owner.login, path: repo.owner.login },
    avatarUrl: repo.owner.avatar_url,
    openPullRequestsCount: repo.open_issues_count,
  };
}

function mapPullRequest(pr) {
  return {
    id: pr.id,
    iid: pr.number,
    projectId: pr.base.repo.full_name,
    title: pr.title,
    description: pr.body,
    state: pr.state === 'open' ? 'opened' : (pr.merged_at ? 'merged' : 'closed'),
    sourceBranch: pr.head.ref,
    targetBranch: pr.base.ref,
    webUrl: pr.html_url,
    sha: pr.head.sha,
    author: pr.user ? { id: pr.user.id, name: pr.user.login, avatarUrl: pr.user.avatar_url } : null,
    assignees: (pr.assignees || []).map(a => ({ id: a.id, name: a.login })),
    labels: (pr.labels || []).map(l => l.name),
    createdAt: pr.created_at,
    updatedAt: pr.updated_at,
    mergedAt: pr.merged_at,
    changesCount: pr.changed_files || 0,
    hasConflicts: false,
    draft: pr.draft || false,
  };
}

module.exports = {
  getRepositories,
  getPullRequests,
  getPullRequestDetails,
  getPullRequestChanges,
  getProjectInfo,
  validateToken,
  cloneRepository,
  fetchChangedFiles,
};
