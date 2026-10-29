FROM ubuntu:24.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 \
        gzip \
 && rm -rf /var/lib/apt/lists/*

# Create directories required at runtime
RUN mkdir -p /app/logs /logs/verifier

# Copy ONLY the pre-generated log files.
# tests/ and solution/ are mounted or copied by the harness, not baked in.
COPY logs/ /app/logs/

WORKDIR /app
