#!/bin/sh
set -e

# Seed a fallback Coraza SPOA config if the API has not generated one yet.
# The coraza-spoa image embeds the OWASP CRS, so no rule download is needed.
mkdir -p /app/data
if [ ! -f /app/data/coraza-spoa.yaml ]; then
    cp /init/coraza-spoa.yaml /app/data/coraza-spoa.yaml
fi
