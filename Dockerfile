# Subfinder is built by ProjectDiscovery; reuse its official versioned image for the binary.
FROM projectdiscovery/subfinder:v2.17.0 AS subfinder

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000 \
    APP_ENV=production \
    SUBFINDER_BIN=/usr/local/bin/subfinder

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin app

COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/subfinder
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app app.py ./app.py
COPY --chown=app:app templates ./templates
COPY --chown=app:app static ./static

USER app
EXPOSE 10000
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 4 --timeout 95 --access-logfile - --error-logfile - app:app"]
