FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    STRAVA_TOKEN_PATH=/data/tokens.json

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
RUN pip install .

RUN useradd --create-home --uid 1000 app && mkdir -p /data && chown -R app:app /data /app
USER app

EXPOSE 8080

CMD ["python", "-m", "strava_mcp.server"]
