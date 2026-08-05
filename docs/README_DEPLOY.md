# RDGen - RustDesk Custom Client Generator

Full-featured web application to generate customized RustDesk clients with your own branding, server configuration, and settings.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Deployment Guide](#deployment-guide)
- [GitHub Setup](#github-setup)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)

## Features

- **Full RustDesk Compilation**: Builds actual RustDesk binaries via GitHub Actions
- **Custom Branding**: Upload your own icon and logo
- **Server Configuration**: Pre-configure your RustDesk server settings
- **Permission Control**: Set default or override permissions
- **Multiple Platforms**: Windows (64/32-bit), Linux, Android, macOS
- **Version Selection**: Build from official releases or nightly
- **Code Patches**: Apply optional UI/UX improvements
- **Save/Load Configs**: Export and import build configurations

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        RDGen Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │   Frontend   │    │   Backend    │    │  GitHub Actions  │  │
│  │   (Next.js)  │◄──►│   (Express)  │◄──►│   (Workflows)    │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│         │                   │                     │              │
│         │                   │                     │              │
│         ▼                   ▼                     ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  User fills  │    │  Triggers    │    │  Builds custom   │  │
│  │  build form  │    │  workflow    │    │  RustDesk client │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Using Docker (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/your-username/rdgen-real.git
cd rdgen-real

# 2. Copy and edit environment file
cp .env.example .env
nano .env  # Add your GITHUB_TOKEN

# 3. Start the application
docker-compose up -d

# 4. Access at http://localhost:5000
```

### Manual Installation

```bash
# Backend
cd backend
npm install
npm run build
npm start

# Frontend (in another terminal)
cd frontend
npm install
npm run build
npm start
```

## Deployment Guide

### Prerequisites

- Docker and Docker Compose (recommended)
- OR Node.js 18+ (manual installation)
- GitHub account with Personal Access Token
- (Optional) Domain name with SSL for production

### Step 1: Fork the RDGen Repository

1. Go to https://github.com/bryangerlach/rdgen
2. Click "Fork" to create your own copy
3. This repository contains the GitHub Actions workflows needed for building

### Step 2: Create GitHub Personal Access Token

1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes:
   - `repo` (full control of private repositories)
   - `workflow` (update GitHub Action workflows)
4. Copy the generated token

### Step 3: Deploy the Application

#### Option A: Docker Deployment

```bash
# Clone this repository
git clone https://github.com/your-username/rdgen-real.git
cd rdgen-real

# Create environment file
cp .env.example .env

# Edit .env with your settings
GITHUB_TOKEN=ghp_your_token_here
GITHUB_OWNER=your-github-username
GITHUB_REPO=rdgen
GEN_URL=http://your-server-ip:5000
PORT=5000

# Start with Docker Compose
docker-compose up -d
```

#### Option B: Manual Deployment

```bash
# Install dependencies
cd backend && npm install && cd ..
cd frontend && npm install && cd ..

# Build applications
cd backend && npm run build && cd ..
cd frontend && npm run build && cd ..

# Start backend (port 4000)
cd backend && PORT=4000 node dist/index.js &

# Start frontend (port 3000)
cd frontend && npm start &

# Set up nginx or another reverse proxy to combine them
```

#### Option C: Systemd Service

```bash
# Copy service file
sudo cp docs/rdgen.service /etc/systemd/system/

# Edit with your paths
sudo nano /etc/systemd/system/rdgen.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable rdgen
sudo systemctl start rdgen
```

### Step 4: Configure Your GitHub Repository

Your forked rdgen repository needs the correct secrets:

1. Go to your forked repo → Settings → Secrets and variables → Actions
2. Add the following secrets:
   - `GENURL`: Your RDGen server URL (e.g., `http://your-server:5000`)

### Step 5: Verify Installation

```bash
# Check health endpoint
curl http://localhost:5000/api/health

# Expected response:
# {"success":true,"data":{"status":"healthy","mockMode":false,...}}
```

## GitHub Setup Checklist

- [ ] Fork https://github.com/bryangerlach/rdgen
- [ ] Create Personal Access Token with `repo` and `workflow` scopes
- [ ] Add `GENURL` secret to forked repository
- [ ] Configure `.env` file on your server
- [ ] Verify webhook connectivity (if using real builds)

### Required Secrets in Your GitHub Repository

| Secret Name | Description | Required |
|-------------|-------------|----------|
| `GENURL` | URL to your RDGen server | Yes |
| `SIGN_BASE_URL` | Code signing server URL | No |
| `SIGN_API_KEY` | Code signing API key | No |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_TOKEN` | GitHub PAT with repo/workflow permissions | Required |
| `GITHUB_OWNER` | GitHub username/organization | `bryangerlach` |
| `GITHUB_REPO` | Repository name | `rdgen` |
| `GEN_URL` | Public URL of this server | `http://localhost:5000` |
| `PORT` | Port to listen on | `5000` |
| `LOG_LEVEL` | Logging level | `info` |
| `NODE_ENV` | Environment mode | `production` |

### Mock Mode

When `GITHUB_TOKEN` is not set, the application runs in "mock mode":
- Build requests are simulated locally
- Progress updates are generated automatically
- Download links return placeholder files
- Useful for testing UI without GitHub integration

## API Reference

### POST /api/build

Start a new build job.

```json
{
  "platform": "windows",
  "version": "1.4.2",
  "configName": "MyClient",
  "appName": "My Remote",
  "host": "rustdesk.example.com",
  "key": "YOUR_PUBLIC_KEY",
  ...
}
```

### GET /api/status/:jobId

Get build job status.

```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "status": "in_progress",
    "progress": 50,
    "statusMessage": "Building...",
    ...
  }
}
```

### GET /api/artifact/:jobId

Download completed build artifact.

### POST /api/cancel/:jobId

Cancel a running build.

### GET /api/health

Health check endpoint.

## Troubleshooting

### "Build failed to start"

1. Check `GITHUB_TOKEN` is valid and has correct permissions
2. Verify repository exists and is accessible
3. Check network connectivity to GitHub API

### "Workflow not found"

1. Ensure workflows are present in your forked repository
2. Check `.github/workflows/` contains generator-*.yml files

### "Artifact not available"

1. Wait for build to complete (can take 10-20 minutes)
2. Check GitHub Actions for build logs
3. Verify `GENURL` secret is correctly set in GitHub

### Mock Mode Always Active

1. Set `GITHUB_TOKEN` in `.env` file
2. Restart the application
3. Check `/api/health` response for `mockMode: false`

### Connection Timeout

1. Increase proxy timeout settings
2. Check firewall allows outbound connections to GitHub
3. Verify server has internet access

## Security Considerations

- Keep `GITHUB_TOKEN` secure - it has repository access
- Use HTTPS in production
- Implement rate limiting for public deployments
- Consider authentication for the web interface
- Regularly rotate access tokens

## License

This project is open source. See the original RDGen repository for license details.

## Credits

- Original RDGen by [Bryan Gerlach](https://github.com/bryangerlach/rdgen)
- RustDesk project: https://rustdesk.com
