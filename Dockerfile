FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py ./
COPY static ./static
ENV PYTHONUNBUFFERED=1 \
    TAILOR_HOST=0.0.0.0 \
    PORT=10000 \
    TAILOR_DB=/var/data/tailor.sqlite3 \
    TAILOR_SECURE_COOKIE=1
RUN mkdir -p /var/data
EXPOSE 10000
CMD ["python", "app.py"]
