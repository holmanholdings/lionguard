# ============================================================
# KILL SWITCH: docker compose -f D:\Lionguard\sandbox\docker-compose.yml down -v --rmi all
# ============================================================
# Lionguard OpenClaw Sandbox — Fully isolated from AOS
# Nothing in this container can access the host filesystem
# except the mounted lionguard source (read-only)

FROM node:22-slim

# Install Python for Lionguard + basic tools
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv curl git \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Install OpenClaw
RUN npm install -g openclaw@latest 2>/dev/null || echo "OpenClaw install attempted"

# Create a Python venv for Lionguard inside the container
RUN python3 -m venv /app/lionguard_env
ENV PATH="/app/lionguard_env/bin:$PATH"
RUN pip install requests

# Working directory for test agents
RUN mkdir -p /app/agents /app/logs /app/data

EXPOSE 18789

CMD ["sleep", "infinity"]
