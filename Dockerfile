FROM python:3.12-slim

# AGT enforces at the application-middleware layer: the policy engine shares a
# process with the agent it governs. The toolkit's own threat model says so and
# recommends one container per agent for OS-level isolation. This image is that
# unit -- AEGIS_AGENT selects which agent the container runs.
WORKDIR /app

RUN adduser --disabled-password --gecos "" --uid 10001 aegis

COPY pyproject.toml ./
RUN pip install --no-cache-dir "agent-governance-toolkit[full]>=4.1.0" \
      "fastapi>=0.110" "uvicorn[standard]>=0.27" "websockets>=12" \
      "pyyaml>=6" "prometheus-client>=0.20"

COPY aegis/ ./aegis/
COPY policies/ ./policies/
COPY config/ ./config/
COPY web/ ./web/

# Policies are mounted read-only in compose; the agent process must never be
# able to rewrite the rules that bind it.
USER aegis
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=20s --timeout=4s --start-period=12s --retries=3 \
  CMD python -c "import urllib.request,sys; \
    sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/state',timeout=3).status==200 else 1)"

EXPOSE 8000
CMD ["python", "-W", "ignore", "-m", "aegis.cli", "serve", "--host", "0.0.0.0"]
