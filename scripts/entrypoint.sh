#!/bin/sh
# Custom entrypoint for SpiderFoot with API key configuration
#
# This script:
# 1. Waits for SpiderFoot to initialize and create its database
# 2. Configures API keys from environment variables
# 3. Starts the SpiderFoot web server

set -e

DB_PATH="/var/lib/spiderfoot/spiderfoot.db"
CONFIG_SCRIPT="/app/scripts/configure_api_keys.py"
CFG_OUTPUT="/var/lib/spiderfoot/spiderfoot.cfg"

echo "=== SpiderFoot OSINT Lab ==="
echo "Starting with API key configuration..."

# Check if we have any API keys to configure
API_KEY_COUNT=$(env | grep -c "^SFP_" || true)
echo "Found $API_KEY_COUNT API key environment variables"

# Generate spiderfoot.cfg file from environment variables
if [ "$API_KEY_COUNT" -gt 0 ] && [ -f "$CONFIG_SCRIPT" ]; then
    echo "Generating API key configuration..."
    python3 "$CONFIG_SCRIPT" --env-file /app/.env --generate-cfg "$CFG_OUTPUT" 2>/dev/null || true

    if [ -f "$CFG_OUTPUT" ]; then
        echo "Generated $CFG_OUTPUT for import"
        echo "API keys will be available after first SpiderFoot startup"
    fi
fi

# Start SpiderFoot (original entrypoint command)
echo "Starting SpiderFoot web server on port 5001..."
exec python3 ./sf.py -l 0.0.0.0:5001
