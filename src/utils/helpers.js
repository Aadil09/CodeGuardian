'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

function sanitizeString(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>"'&]/g, (char) => ({
    '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '&': '&amp;'
  }[char]));
}

function generateScanId() {
  return crypto.randomBytes(16).toString('hex');
}

function ensureDirectoryExists(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

function deleteDirRecursive(dirPath) {
  if (fs.existsSync(dirPath)) {
    fs.rmSync(dirPath, { recursive: true, force: true });
  }
}

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function isSupportedFile(filePath) {
  const supported = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.json', '.env', '.yaml', '.yml', '.xml', '.html', '.ejs', '.php', '.py', '.java', '.cs', '.go', '.rb', '.sh', '.bash'];
  return supported.includes(path.extname(filePath).toLowerCase());
}

function isExcludedPath(filePath) {
  const excluded = ['node_modules', '.git', 'dist', 'build', 'coverage', '.nyc_output', 'vendor', '__pycache__'];
  return excluded.some(ex => filePath.includes(path.sep + ex + path.sep) || filePath.includes('/' + ex + '/'));
}

function paginateArray(array, page = 1, limit = 20) {
  const start = (page - 1) * limit;
  return {
    data: array.slice(start, start + limit),
    total: array.length,
    page,
    limit,
    totalPages: Math.ceil(array.length / limit),
  };
}

function groupBy(array, key) {
  return array.reduce((acc, item) => {
    const group = item[key];
    if (!acc[group]) acc[group] = [];
    acc[group].push(item);
    return acc;
  }, {});
}

module.exports = {
  sanitizeString,
  generateScanId,
  ensureDirectoryExists,
  deleteDirRecursive,
  formatBytes,
  isSupportedFile,
  isExcludedPath,
  paginateArray,
  groupBy,
};
