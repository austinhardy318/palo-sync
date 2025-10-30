# NMS-Sync

[![CI/CD Pipeline](https://github.com/austinhardy318/nms-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/austinhardy318/nms-sync/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

NMS-Sync is a Dockerized web application for synchronizing network management system (NMS) configurations from production to lab environments. **Currently supports Palo Alto Networks Panorama**, with plans to support additional NMS platforms in the future.

> **⚠️ Disclaimer**: "Panorama" and "Palo Alto Networks" are trademarks of Palo Alto Networks, Inc. This project is not affiliated with, endorsed by, or sponsored by Palo Alto Networks. NMS-Sync is an independent, open-source project.

## What It Does

NMS-Sync provides a safe and automated way to:
- **Sync configurations** from production Panorama to lab/test environments
- **Preview changes** before applying them with built-in diff checking
- **Automatically backup** configurations before sync operations
- **Manage backups** with restore, download, and cleanup capabilities
- **Track all operations** with detailed activity logs

## Features

- 🔄 **One-Way Sync**: Safely synchronize production configuration to lab environment
- 🔍 **Diff Checking**: Preview all changes before synchronizing
- 💾 **Automatic Backups**: Creates timestamped backups before sync operations
- 🏷️ **Hostname Preservation**: Keeps lab hostname unchanged during sync
- 🔐 **Flexible Authentication**: Supports API keys or username/password for Panorama, plus RADIUS for web access
- 🌐 **Web Interface**: Modern, user-friendly GUI for all operations
- 📊 **Activity Logging**: Track all operations with user attribution
- ⚙️ **Configurable Settings**: Customize timeout, timezone, and diff ignore rules

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Network access to production and lab Panorama instances
- Valid credentials (username/password or API key) for both Panorama instances
- Sufficient privileges on lab Panorama to modify configuration

### 5-Minute Setup

1. **Create `docker-compose.yml`**:
   ```yaml
   services:
     nms-sync:
       image: ghcr.io/austinhardy318/nms-sync:latest
       container_name: nms-sync
       ports:
         - "5001:5000"
       volumes:
         - ./backups:/backups
         - ./logs:/app/logs
         - ./settings:/app/settings
       environment:
         # Production Panorama Configuration
         - PROD_NMS_HOST=${PROD_NMS_HOST}
         - PROD_NMS_USERNAME=${PROD_NMS_USERNAME}
         - PROD_NMS_PASSWORD=${PROD_NMS_PASSWORD}
         - PROD_NMS_API_KEY=${PROD_NMS_API_KEY}
         
         # Lab Panorama Configuration
         - LAB_NMS_HOST=${LAB_NMS_HOST}
         - LAB_NMS_HOSTNAME=${LAB_NMS_HOSTNAME}
         - LAB_NMS_USERNAME=${LAB_NMS_USERNAME}
         - LAB_NMS_PASSWORD=${LAB_NMS_PASSWORD}
         - LAB_NMS_API_KEY=${LAB_NMS_API_KEY}
         
         # Flask Configuration
         - FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
         - SSL_VERIFY=${SSL_VERIFY:-false}
         
         # Web GUI Authentication (optional)
         - GUI_USERNAME=${GUI_USERNAME}
         - GUI_PASSWORD=${GUI_PASSWORD}
       restart: unless-stopped
   ```

2. **Create `.env` file**:
   ```env
   # Production Panorama Configuration
   PROD_NMS_HOST=prod-panorama.example.com
   PROD_NMS_USERNAME=admin
   PROD_NMS_PASSWORD=your_password_here
   # PROD_NMS_API_KEY=your_api_key_here
   
   # Lab Panorama Configuration
   LAB_NMS_HOST=lab-panorama.example.com
   LAB_NMS_USERNAME=admin
   LAB_NMS_PASSWORD=your_password_here
   # LAB_NMS_API_KEY=your_api_key_here
   
   # Flask Configuration
   FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
   
   # Web GUI Authentication (optional)
   GUI_USERNAME=admin
   GUI_PASSWORD=changeme
   ```

3. **Start the application**:
   ```bash
   docker compose up -d
   ```

4. **Access the web interface**:
   ```
   http://localhost:5001
   ```

That's it! You can now use the web interface to sync configurations between your Panorama instances.

### Building from Source

If you prefer to build from source:

```bash
git clone https://github.com/austinhardy318/nms-sync.git
cd nms-sync
cp env.example .env
# Edit .env with your credentials
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

## Usage

### Basic Workflow

1. **Check Status**: Click "Refresh Status" to verify connections to both Panorama instances
2. **Preview Changes**: Click "Run Diff Check" to see what will change
3. **Sync Configuration**: 
   - Ensure "Create backup before sync" is checked (recommended)
   - Click "Execute Sync" to synchronize production configuration to lab
4. **Monitor**: Watch the activity log for operation details

### Management Script

NMS-Sync includes a convenient management script (`manage.sh`):

```bash
./manage.sh start     # Start the application
./manage.sh stop      # Stop the application
./manage.sh restart   # Restart the application
./manage.sh logs      # View application logs
./manage.sh status    # Check container status
./manage.sh shell     # Open shell in container
```

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `PROD_NMS_HOST` | Production Panorama hostname or IP |
| `PROD_NMS_USERNAME` / `PROD_NMS_PASSWORD` | Production Panorama credentials (or use `PROD_NMS_API_KEY`) |
| `LAB_NMS_HOST` | Lab Panorama hostname or IP |
| `LAB_NMS_USERNAME` / `LAB_NMS_PASSWORD` | Lab Panorama credentials (or use `LAB_NMS_API_KEY`) |
| `FLASK_SECRET_KEY` | Flask secret key (generate with: `python -c "import secrets; print(secrets.token_hex(32))"`) |

### Optional Environment Variables

| Variable | Description |
|----------|-------------|
| `LAB_NMS_HOSTNAME` | Lab hostname to preserve during sync |
| `GUI_USERNAME` / `GUI_PASSWORD` | Web GUI authentication credentials |
| `RADIUS_ENABLED` | Enable RADIUS authentication (true/false) |
| `SSL_VERIFY` | Enable SSL verification (default: false) |

**Note**: Either username/password OR API key is required for each Panorama instance.

## REST API

NMS-Sync provides a REST API for programmatic access:

```bash
# Check connection status
curl http://localhost:5001/api/status

# Preview changes
curl -X POST http://localhost:5001/api/diff

# Execute sync
curl -X POST http://localhost:5001/api/sync \
  -H "Content-Type: application/json" \
  -d '{"create_backup": true}'
```

Full API documentation: See `/api/status`, `/api/diff`, `/api/sync`, `/api/backups`, `/api/logs`, `/api/settings`

## Troubleshooting

### Common Issues

- **Cannot connect to Panorama**: Verify hostnames, credentials, and network connectivity
- **Sync fails**: Check logs with `./manage.sh logs` or verify lab Panorama has commit privileges
- **Timeout errors**: Adjust timeout settings in the Settings page
- **SSL errors**: Set `SSL_VERIFY=false` in `.env` for lab environments

### Viewing Logs

```bash
# Using management script
./manage.sh logs

# Using docker compose
docker compose logs -f nms-sync
```

## Roadmap

NMS-Sync currently supports **Palo Alto Networks Panorama**. Future versions may include support for:

- Other network management systems
- Additional configuration synchronization features
- Enhanced diff visualization
- Batch synchronization capabilities

## Security Best Practices

1. **API Keys**: Prefer API keys over passwords when possible
2. **Read-Only Access**: Use read-only API access for production Panorama where possible
3. **Secure Storage**: Never commit `.env` file to version control
4. **Network Security**: Restrict network access to the Docker container
5. **GUI Authentication**: Always set `GUI_USERNAME` and `GUI_PASSWORD` in production

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Disclaimer

**⚠️ Important**: This tool modifies Panorama configurations. Always test in a lab environment first and ensure you have proper backups before using in production. NMS-Sync software is provided "as is" without warranty of any kind.

**Trademark Notice**: "Panorama" and "Palo Alto Networks" are trademarks of Palo Alto Networks, Inc. This project is not affiliated with, endorsed by, or sponsored by Palo Alto Networks.

## Support

For issues or questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review application logs
3. Check the [Issues](https://github.com/austinhardy318/nms-sync/issues) page
