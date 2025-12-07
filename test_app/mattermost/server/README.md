# Mattermost Server - Docker Deployment

This directory contains the Docker configuration for building and deploying Mattermost server from source.

## Prerequisites

- Docker
- Docker Compose

## Quick Start

1. Build and start the services:
   ```bash
   docker-compose up -d
   ```

2. Access Mattermost at: http://localhost:8065

3. View logs:
   ```bash
   docker-compose logs -f mattermost
   ```

## Configuration

### Environment Variables

The following environment variables can be configured in `docker-compose.yml`:

- `MM_SQLSETTINGS_DRIVERNAME`: Database driver (default: postgres)
- `MM_SQLSETTINGS_DATASOURCE`: Database connection string
- `MM_SERVICESETTINGS_SITEURL`: Site URL for Mattermost
- `MM_SERVICESETTINGS_ENABLELOCALMODE`: Enable local mode for CLI tools

### Mattermost Version

To build a different version of Mattermost, modify the `MATTERMOST_VERSION` build arg in `docker-compose.yml`:

```yaml
args:
  MATTERMOST_VERSION: v9.5.1  # Change to desired version
```

## Management Commands

### Start services
```bash
docker-compose up -d
```

### Stop services
```bash
docker-compose down
```

### Rebuild from source
```bash
docker-compose build --no-cache
docker-compose up -d
```

### View logs
```bash
docker-compose logs -f
```

### Remove all data (CAUTION: This will delete all data)
```bash
docker-compose down -v
```

## Volumes

The deployment uses the following volumes for persistent data:

- `postgres_data`: PostgreSQL database files
- `mattermost_data`: Mattermost data files
- `mattermost_logs`: Mattermost log files
- `mattermost_config`: Mattermost configuration
- `mattermost_plugins`: Mattermost plugins

## Troubleshooting

### Check service status
```bash
docker-compose ps
```

### Check service health
```bash
docker-compose exec mattermost curl http://localhost:8065/api/v4/system/ping
```

### Access PostgreSQL
```bash
docker-compose exec postgres psql -U mmuser -d mattermost
```

### Reset admin password
```bash
docker-compose exec mattermost /mattermost/bin/mattermost user password <username> <new-password>
```
