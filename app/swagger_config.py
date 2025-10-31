"""
Swagger/OpenAPI configuration for NMS-Sync API
"""

SWAGGER_CONFIG = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/api/docs",
    "title": "NMS-Sync API Documentation",
    "version": "1.0.0",
    "description": """
    REST API for synchronizing Palo Alto Networks Panorama configurations
    from production to lab environments.
    
    ## Authentication
    All API endpoints require authentication via session cookies.
    Use the `/login` endpoint to authenticate first.
    
    ## Rate Limiting
    API endpoints are rate-limited:
    - Default: 200 requests per day, 50 per hour
    - Per-user limits for authenticated users
    - IP-based limits for anonymous users
    
    ## Error Responses
    All errors follow this format:
    ```json
    {
      "success": false,
      "error": {
        "message": "Error description",
        "code": "ERROR_CODE",
        "details": {}
      }
    }
    ```
    """,
    "termsOfService": "",
    "contact": {
        "name": "NMS-Sync Support"
    },
    "license": {
        "name": "MIT"
    },
    "tags": [
        {
            "name": "Status",
            "description": "Connection status and health checks"
        },
        {
            "name": "Sync",
            "description": "Configuration synchronization operations"
        },
        {
            "name": "Diff",
            "description": "Configuration difference generation"
        },
        {
            "name": "Backups",
            "description": "Backup management operations"
        },
        {
            "name": "Settings",
            "description": "Application settings management"
        },
        {
            "name": "Logs",
            "description": "Operation logs and audit trail"
        }
    ]
}

