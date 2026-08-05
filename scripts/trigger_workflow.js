#!/usr/bin/env node
/**
 * trigger_workflow.js - Trigger GitHub Actions workflow for RDGen builds
 *
 * Usage:
 *   node trigger_workflow.js --config ./build_config.json
 *   node trigger_workflow.js --platform windows --version 1.4.2 --host myserver.com --key MYKEY
 *
 * Environment Variables:
 *   GITHUB_TOKEN - GitHub Personal Access Token with repo and workflow permissions
 *   GITHUB_OWNER - GitHub username/organization (default: nextcoreti)
 *   GITHUB_REPO  - GitHub repository name (default: rdgen)
 */

const https = require('https');
const { v4: uuidv4 } = require('uuid');

// Parse command line arguments
const args = process.argv.slice(2);
const options = {};

for (let i = 0; i < args.length; i += 2) {
  const key = args[i].replace(/^--/, '');
  const value = args[i + 1];
  options[key] = value;
}

// Configuration
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER || 'nextcoreti';
const GITHUB_REPO = process.env.GITHUB_REPO || 'rdgen';

if (!GITHUB_TOKEN) {
  console.error('ERROR: GITHUB_TOKEN environment variable is required');
  console.error('Create a token at https://github.com/settings/tokens with repo and workflow permissions');
  process.exit(1);
}

// Load config from file or use command line options
let config;
if (options.config) {
  config = require(options.config);
} else {
  config = {
    platform: options.platform || 'windows',
    version: options.version || '1.4.2',
    host: options.host || 'rs-ny.rustdesk.com',
    key: options.key || 'OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=',
    apiServer: options.api || '',
    appName: options.appname || 'rustdesk',
    filename: options.filename || 'rustdesk',
  };
}

// Build workflow inputs
const uuid = uuidv4();
const customJson = {
  'override-settings': {},
  'default-settings': {},
};
const customBase64 = Buffer.from(JSON.stringify(customJson)).toString('base64');

const extrasJson = {
  version: config.version,
  rdgen: 'true',
  cycleMonitor: 'false',
  xOffline: 'false',
  removeNewVersionNotif: 'false',
  compname: 'Purslane Ltd',
  urlLink: 'https://rustdesk.com',
  downloadLink: 'https://rustdesk.com/download',
  delayFix: 'false',
};

const workflowInputs = {
  server: config.host,
  key: config.key,
  apiServer: config.apiServer || `https://${config.host}:21114`,
  custom: customBase64,
  uuid: uuid,
  iconlink: 'false',
  logolink: 'false',
  appname: config.appName,
  filename: config.filename,
  extras: JSON.stringify(extrasJson),
};

// Determine workflow file
const workflowMap = {
  windows: 'generator-windows.yml',
  'windows-x86': 'generator-windows-x86.yml',
  linux: 'generator-linux.yml',
  android: 'generator-android.yml',
  macos: 'generator-macos.yml',
};
const workflowFile = workflowMap[config.platform] || 'generator-windows.yml';

// Trigger workflow
console.log('=== RDGen Workflow Trigger ===');
console.log(`Platform: ${config.platform}`);
console.log(`Version: ${config.version}`);
console.log(`Workflow: ${workflowFile}`);
console.log(`UUID: ${uuid}`);
console.log('');

const postData = JSON.stringify({
  ref: 'master',
  inputs: workflowInputs,
});

const requestOptions = {
  hostname: 'api.github.com',
  port: 443,
  path: `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/${workflowFile}/dispatches`,
  method: 'POST',
  headers: {
    'Accept': 'application/vnd.github+json',
    'Authorization': `Bearer ${GITHUB_TOKEN}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'RDGen-Trigger',
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(postData),
  },
};

const req = https.request(requestOptions, (res) => {
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  res.on('end', () => {
    if (res.statusCode === 204) {
      console.log('SUCCESS: Workflow triggered!');
      console.log(`Monitor at: https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/actions`);
      console.log(`Job UUID: ${uuid}`);
    } else {
      console.error(`ERROR: HTTP ${res.statusCode}`);
      console.error(data);
      process.exit(1);
    }
  });
});

req.on('error', (error) => {
  console.error('ERROR:', error.message);
  process.exit(1);
});

req.write(postData);
req.end();
