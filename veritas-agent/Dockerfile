FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py veritas_recognizers.py ./

# Release version reported to the server (docker build --build-arg VERSION=1.0.18 ...)
ARG VERSION=dev
ENV VERITAS_AGENT_VERSION=$VERSION

# Expected at runtime (see k8s/ for a working DaemonSet):
#   the config file, passed with --config (a ConfigMap in Kubernetes)
#   a writable state directory for the agent's identity: set VERITAS_STATE_DIR to it
#     (do NOT mount a volume over /app, which holds agent.py)
#   the logs to read (for example the node's /var/log), read-only
#   /var/run/docker.sock only if you use "docker" sources

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["python", "agent.py"]
