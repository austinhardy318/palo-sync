FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Note: Tests are not included in the image
# Mount tests directory as volume when running tests

# Create volume for backups
RUN mkdir -p /backups && chmod 777 /backups

# Expose port
EXPOSE 5000

# Note: Healthcheck is configured in docker-compose.yml

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Run the application with Gunicorn (default command)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app.main:app"]

