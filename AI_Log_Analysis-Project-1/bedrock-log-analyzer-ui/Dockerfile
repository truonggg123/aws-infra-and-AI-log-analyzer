FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (supervisor + cron for auto pipeline)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    supervisor \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY streamlit_app.py .
COPY cloudwatch_client.py .
COPY auto_analyzer.py .
COPY incident_store.py .
COPY correlation_rules.json .
COPY src/ ./src/

# Copy config files
COPY .env.example .env.example
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Setup cron job for auto analysis (every 5 minutes)
COPY crontab /etc/cron.d/log-analyzer
RUN chmod 0644 /etc/cron.d/log-analyzer \
    && crontab /etc/cron.d/log-analyzer

# Create data directories
RUN mkdir -p /data/incidents /var/log

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Run supervisord (manages both cron + streamlit)
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
