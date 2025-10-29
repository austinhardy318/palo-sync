# Palo-Sync

[![CI/CD Pipeline](https://github.com/austinhardy318/palo-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/austinhardy318/palo-sync/actions/workflows/ci.yml)

A Dockerized Flask web application for synchronizing Palo Alto Panorama configurations from production to lab environments. Features automatic backups, configuration diff checking, and a user-friendly web interface.

**Disclaimer**: "Panorama" and "Palo Alto Networks" are trademarks of Palo Alto Networks, Inc. This project is not affiliated with, endorsed by, or sponsored by Palo Alto Networks.

## Features

- **One-Way Sync**: Synchronize production Panorama configuration to lab environment
- **Diff Checking**: Preview changes before synchronizing
- **Automatic Backups**: Creates timestamped backups before sync operations
- **Hostname Preservation**: Automatically preserves lab hostname during sync
- **Dual Authentication**: Supports both username/password and API key authentication for Panorama
- **Web Authentication**: Login page with support for local accounts and RADIUS
- **Multi-Page Interface**: Separate pages for operations (Home) and configuration (Settings)
- **Web GUI**: Modern web interface for easy management
- **Activity Logging**: Track all operations with username attribution
- **Backup Management**: List, download, and restore from previous backups
- **Backup Cleanup**: Delete all backups with confirmation
- **Settings Management**: Persistent settings saved to disk

## Prerequisites

- Docker and Docker Compose installed
- Network access to both production and lab Panorama instances
- Valid credentials (username/password or API key) for both Panorama instances
- Sufficient privileges on lab Panorama to modify configuration

## Quick Start

### Installation

There are two ways to run Palo-Sync:

#### Option 1: Using Pre-built Image (Recommended)

1. **Clone this repository for configuration files**
   ```bash
   git clone https://github.com/austinhardy318/palo-sync.git
   cd palo-sync
   ```

2. **Copy and edit the environment file**
   ```bash
   cp .env.example .env
   # Edit .env with your credentials (see Option 2, step 3 for details)
   ```

3. **Start the container**
   
   The `docker-compose.yml` file is pre-configured to use the pre-built image:
   ```bash
   docker-compose up -d
   ```
   
   Or if you want to build from source locally:
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
   ```

4. **Access the application at http://localhost:5001**

#### Option 2: Building from Source

1. **Clone this repository**
   ```bash
   git clone https://github.com/austinhardy318/palo-sync.git
   cd palo-sync
   ```

2. **Copy the environment file template**
   ```bash
   cp .env.example .env
   ```

3. **Edit `.env` file with your Panorama credentials**
   ```env
   # Production Panorama Configuration
   PROD_PANORAMA_HOST=prod-panorama.example.com
   PROD_PANORAMA_USERNAME=admin
   PROD_PANORAMA_PASSWORD=your_password_here
   # PROD_PANORAMA_API_KEY=your_api_key_here

   # Lab Panorama Configuration
   LAB_PANORAMA_HOST=lab-panorama.example.com
   LAB_PANORAMA_USERNAME=admin
   LAB_PANORAMA_PASSWORD=your_password_here
   # LAB_PANORAMA_API_KEY=your_api_key_here

   # Web GUI Authentication (optional)
   GUI_USERNAME=admin
   GUI_PASSWORD=changeme

   # RADIUS Authentication (optional)
   RADIUS_ENABLED=false
   RADIUS_SERVER=radius.example.com
   RADIUS_SECRET=your_secret
   ```

   **Note**: If Panorama API keys are provided, they will be used automatically. Otherwise, username/password will be used.

4. **Build and start the container**
   
   Using the management script (recommended):
   ```bash
   ./manage.sh start
   ```
   
   Or using docker-compose with build file:
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
   ```

5. **Access the application**
   ```
   http://localhost:5001
   ```
   
   **Note**: If you configured `GUI_USERNAME` and `GUI_PASSWORD`, you'll be prompted to login. Leave these empty for quick testing without authentication.

**Note**: Palo-Sync is provided "as is" under the GPL-3.0 license. Always test in a lab environment first before using in production.

## Management Script

Palo-Sync includes a convenient management script (`manage.sh`) for common operations:

```bash
./manage.sh start     # Start the application
./manage.sh stop      # Stop the application
./manage.sh restart   # Restart the application
./manage.sh logs      # View application logs (follow mode)
./manage.sh status    # Check container status
./manage.sh rebuild   # Rebuild containers with no cache
./manage.sh shell     # Open shell in container
./manage.sh backup    # List backup files
./manage.sh clean     # Remove containers and clean up
./manage.sh           # Show help message
```

For example, to view logs:
```bash
./manage.sh logs
```

The script provides a simpler interface than using `docker-compose` commands directly.

## Usage

### First Sync

1. Click **"Refresh Status"** to verify connections to both Panorama instances
2. Click **"Run Diff Check"** to see what changes will be made
3. Ensure **"Create backup before sync"** is checked (recommended)
4. Click **"Execute Sync"** to sync production configuration to lab
5. Monitor the activity log for operation details

### Workflow

1. **Check Status**: The status section shows connection status to both Panorama instances
2. **Run Diff Check**: Click "Run Diff Check" to preview what changes will be made
3. **Review Differences**: Review the diff summary and details
4. **Execute Sync**: Click "Execute Sync" to perform the synchronization
   - Enable backup creation (recommended) to create a timestamped backup before sync
5. **Monitor Results**: Check the activity log and sync results

### Hostname Preservation

By default, the lab Panorama hostname is automatically preserved during sync operations. This prevents the production hostname from overwriting the lab hostname. This feature can be enabled/disabled in the Settings page.

### Backup Management

- All backups are stored in the `backups/` directory
- Backups are automatically created before sync operations (if enabled)
- Use the "Restore" button to restore a previous configuration
- Backups can be downloaded directly from the host filesystem

### Settings Page

The Settings page (accessible via navigation) allows you to:
- Configure default sync behavior (create backup, commit configuration)
- Enable/disable hostname preservation
- View connection information
- Manage backups (delete all backups)
- Settings are saved to disk and persist across container restarts

### Authentication

The application supports multiple authentication methods:

#### Web GUI Authentication Options

1. **Local Authentication** (Simple)
   - Set `GUI_USERNAME` and `GUI_PASSWORD` in `.env` file
   - Basic username/password authentication

2. **RADIUS Authentication** (Advanced)
   - Set `RADIUS_ENABLED=true` in `.env` file
   - Configure RADIUS server settings (`RADIUS_SERVER`, `RADIUS_SECRET`, etc.)
   - Users can authenticate with their RADIUS credentials

3. **Combined Approach**
   - Can use both local and RADIUS authentication
   - Local accounts checked first, then RADIUS if user not found

**Note**: All authentication attempts are logged with username attribution in the Activity Log.

### REST API Endpoints

The application also provides a REST API for programmatic access:

- `GET /api/status` - Get connection status
- `POST /api/diff` - Generate configuration diff
- `POST /api/sync` - Execute synchronization
- `GET /api/backups` - List available backups
- `POST /api/backups/restore` - Restore a backup
- `POST /api/backups/delete` - Delete a backup
- `POST /api/backups/cleanup` - Delete all backups
- `GET /api/backups/download/<filename>` - Download a backup
- `GET /api/logs` - Get operation logs
- `GET /api/settings` - Get application settings
- `POST /api/settings` - Save application settings

Example API usage:
```bash
# Check status
curl http://localhost:5001/api/status

# Run diff
curl -X POST http://localhost:5001/api/diff

# Execute sync
curl -X POST http://localhost:5001/api/sync \
  -H "Content-Type: application/json" \
  -d '{"create_backup": true}'
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PROD_PANORAMA_HOST` | Yes | Production Panorama hostname or IP |
| `PROD_PANORAMA_USERNAME` | Yes* | Production Panorama username |
| `PROD_PANORAMA_PASSWORD` | Yes* | Production Panorama password |
| `PROD_PANORAMA_API_KEY` | Yes* | Production Panorama API key |
| `LAB_PANORAMA_HOST` | Yes | Lab Panorama hostname or IP |
| `LAB_PANORAMA_USERNAME` | Yes* | Lab Panorama username |
| `LAB_PANORAMA_PASSWORD` | Yes* | Lab Panorama password |
| `LAB_PANORAMA_API_KEY` | Yes* | Lab Panorama API key |
| `LAB_PANORAMA_HOSTNAME` | No | Lab hostname to preserve during sync |
| `GUI_USERNAME` | No | Web GUI username for local auth |
| `GUI_PASSWORD` | No | Web GUI password for local auth |
| `RADIUS_ENABLED` | No | Enable RADIUS authentication (true/false) |
| `RADIUS_SERVER` | Yes** | RADIUS server hostname or IP |
| `RADIUS_PORT` | No | RADIUS server port (default: 1812) |
| `RADIUS_SECRET` | Yes** | RADIUS shared secret |
| `FLASK_SECRET_KEY` | Yes | Flask secret key for session security (generate with: `python -c "import secrets; print(secrets.token_hex(32))"`) |
| `SSL_VERIFY` | No | Enable SSL verification (default: false) |

*Either username/password OR API key is required for each Panorama instance  
**Required if RADIUS_ENABLED=true

### Security Best Practices

1. **API Keys**: Prefer API keys over passwords when possible
2. **Read-Only Access**: Use read-only API access for production Panorama where possible
3. **Secure Storage**: Never commit `.env` file to version control
4. **Network Security**: Restrict network access to the Docker container
5. **GUI Authentication**: Consider setting `GUI_USERNAME` and `GUI_PASSWORD` in production environments

## Troubleshooting

### Connection Issues

- **Cannot connect to Panorama**: Verify hostnames, credentials, and network connectivity
- **API key not working**: Ensure the API key has sufficient permissions
- **Timeout errors**: Check firewall rules and network latency
- **SSL certificate errors**: Set `SSL_VERIFY=false` in `.env` for lab environments

### Sync Issues

- **Sync fails mid-operation**: Check logs for specific errors
- **Configuration not applied**: Verify lab Panorama has commit privileges
- **Large configs timeout**: Increase timeout settings in Docker if needed

### Authentication Issues

- **Login fails**: Verify `GUI_USERNAME` and `GUI_PASSWORD` in `.env` are set correctly
- **RADIUS not working**: Check RADIUS configuration and network connectivity
- **Session timeout**: Sessions expire after 8 hours of inactivity

### Viewing Logs

View container logs using the management script:
```bash
./manage.sh logs
```

Or using docker-compose directly:
```bash
docker-compose logs -f palo-sync
```

View operation logs in the web interface under "Activity Log" section

### Resetting

To reset the application using the management script:
```bash
./manage.sh restart
```

Or using docker-compose directly:
```bash
docker-compose down
docker-compose up -d
```

## Files and Directories

```
.
├── app/
│   ├── __init__.py           # Package initialization
│   ├── main.py               # Flask application
│   ├── config.py             # Configuration management
│   ├── auth.py               # Authentication module
│   ├── panorama_sync.py      # Core sync logic
│   ├── templates/
│   │   ├── index.html        # Home page
│   │   ├── settings.html     # Settings page
│   │   └── login.html        # Login page
│   └── static/
│       ├── style.css         # Stylesheet
│       ├── script.js         # Home page JavaScript
│       └── settings.js       # Settings page JavaScript
├── backups/                  # Backup storage (volume mount)
├── logs/                     # Application logs (volume mount)
├── settings/                 # Settings storage (volume mount)
│   └── user_settings.json    # Application settings
├── documentation/            # Development documentation
│   └── api-guide/            # Palo Alto API reference
├── Dockerfile                # Docker image definition
├── docker-compose.yml        # Docker Compose configuration (uses pre-built image)
├── docker-compose.build.yml  # Docker Compose override for building from source
├── requirements.txt          # Python dependencies
├── manage.sh                 # Management script
├── .env.example              # Environment template
├── .env                      # Environment file (not in git)
└── README.md                 # This file
```

## Backup Location

Backups are stored in the `backups/` directory on the host filesystem. Each backup is named:

```
{env}_backup_{timestamp}.xml
```

For example:
```
lab_backup_20240115_143022.xml
```

## Limitations

- This is a one-way sync: changes are pushed from production to lab only
- Large configurations may take several minutes to process
- Rollback requires manual backup restoration
- Network latency affects sync performance

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

**Disclaimer**: Palo-Sync software is provided "as is" without warranty of any kind. Always test in a lab environment first and ensure you have proper backups before using in production.

## Support

For issues or questions, please check the troubleshooting section or review the application logs.

---

**Warning**: This tool modifies Panorama configurations. Always test in a lab environment first and ensure you have proper backups before using in production.

