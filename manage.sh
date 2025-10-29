#!/bin/bash
# Palo-Sync Management Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$1" in
    start)
        echo "Starting Palo-Sync..."
        docker-compose up -d
        echo "Application started. Access at http://localhost:5001"
        ;;
    stop)
        echo "Stopping Palo-Sync..."
        docker-compose down
        ;;
    restart)
        echo "Restarting Palo-Sync..."
        docker-compose down
        docker-compose up -d
        ;;
    logs)
        docker-compose logs -f palo-sync
        ;;
    status)
        docker-compose ps
        ;;
    rebuild)
        echo "Rebuilding containers..."
        docker-compose down
        docker-compose build --no-cache
        docker-compose up -d
        echo "Rebuild complete. Access at http://localhost:5001"
        ;;
    shell)
        docker-compose exec palo-sync /bin/bash
        ;;
    backup)
        echo "Available backups:"
        ls -lh backups/ | grep -v "^d" | grep -v total
        ;;
    clean)
        echo "Cleaning up old containers and images..."
        docker-compose down -v
        docker system prune -f
        ;;
    *)
        echo "Palo-Sync Management"
        echo ""
        echo "Usage: $0 {start|stop|restart|logs|status|rebuild|shell|backup|clean}"
        echo ""
        echo "Commands:"
        echo "  start    - Start the application"
        echo "  stop     - Stop the application"
        echo "  restart  - Restart the application"
        echo "  logs     - View application logs"
        echo "  status   - Check container status"
        echo "  rebuild  - Rebuild containers with no cache"
        echo "  shell    - Open shell in container"
        echo "  backup   - List backup files"
        echo "  clean    - Remove containers and clean up"
        exit 1
        ;;
esac

