# RDGen Real - RustDesk Custom Client Generator

Generate fully customized RustDesk clients with your own branding, server configuration, and settings. This implementation uses GitHub Actions to compile actual RustDesk binaries.

## Quick Start

```bash
# 1. Copy environment file
cp .env.example .env

# 2. Add your GitHub token
nano .env

# 3. Start with Docker
docker-compose up -d

# 4. Open http://localhost:5000
```

## Features

- Full RustDesk compilation via GitHub Actions
- Custom icon and logo support
- Pre-configured server settings
- Permission control (default/override)
- Multiple platforms (Windows, Linux, Android, macOS)
- Save/load build configurations

## Requirements

- Docker and Docker Compose
- GitHub account with Personal Access Token

## Documentation

See [docs/README_DEPLOY.md](docs/README_DEPLOY.md) for full deployment guide.

## Project Structure

```
rdgen-real/
├── frontend/          # Next.js web interface
├── backend/           # Express.js API server
├── workflows/         # GitHub Actions workflow files
├── patches/           # RustDesk source patches
├── scripts/           # Utility scripts
├── docs/              # Documentation
├── docker-compose.yml # Docker configuration
└── nginx.conf         # Nginx reverse proxy config
```

## License

See original project: https://github.com/bryangerlach/rdgen
