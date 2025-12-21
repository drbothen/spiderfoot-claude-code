#!/bin/sh
# Custom entrypoint for SpiderFoot with API key configuration
#
# This script:
# 1. Generates API key config from environment variables
# 2. Starts SpiderFoot in the background
# 3. Waits for SpiderFoot to be ready
# 4. Imports API keys automatically
# 5. Keeps SpiderFoot running in foreground

set -e

CONFIG_SCRIPT="/app/scripts/configure_spiderfoot.py"
CFG_OUTPUT="/var/lib/spiderfoot/spiderfoot.cfg"
SF_URL="http://localhost:5001"

echo "=== SpiderFoot OSINT Lab ==="
echo "Starting with API key configuration..."

# Copy custom modules if they exist
CUSTOM_MODULES="/home/spiderfoot/modules-custom"
if [ -d "$CUSTOM_MODULES" ] && [ "$(ls -A $CUSTOM_MODULES 2>/dev/null)" ]; then
    echo "Installing custom modules..."
    cp -v "$CUSTOM_MODULES"/*.py /home/spiderfoot/modules/ 2>/dev/null || true
fi

# Check if we have any API keys to configure
API_KEY_COUNT=$(env | grep -c "^SFP_" || true)
echo "Found $API_KEY_COUNT API key environment variables"

# Generate spiderfoot.cfg file from environment variables
if [ "$API_KEY_COUNT" -gt 0 ] && [ -f "$CONFIG_SCRIPT" ]; then
    echo "Generating API key configuration..."
    python3 "$CONFIG_SCRIPT" --env-file /app/.env --generate-cfg "$CFG_OUTPUT" 2>/dev/null || true

    if [ -f "$CFG_OUTPUT" ]; then
        echo "Generated $CFG_OUTPUT"
    fi
fi

# Start SpiderFoot in background
echo "Starting SpiderFoot web server on port 5001..."
python3 ./sf.py -l 0.0.0.0:5001 &
SF_PID=$!

# Wait for SpiderFoot to be ready
echo "Waiting for SpiderFoot to be ready..."
RETRIES=30
while [ $RETRIES -gt 0 ]; do
    if wget -q --spider "$SF_URL" 2>/dev/null; then
        echo "SpiderFoot is ready!"
        break
    fi
    RETRIES=$((RETRIES - 1))
    sleep 1
done

# Auto-import API keys if config file exists
if [ -f "$CFG_OUTPUT" ] && [ "$API_KEY_COUNT" -gt 0 ]; then
    echo "Auto-importing API keys..."
    python3 "$CONFIG_SCRIPT" --generate-cfg "$CFG_OUTPUT" --import --url "$SF_URL" 2>&1 || echo "Import completed with warnings"
fi

echo ""
echo "=== SpiderFoot Ready ==="
echo "Web UI: http://localhost:5001"
echo "API keys: $API_KEY_COUNT configured"
echo ""

# Keep container running by waiting on SpiderFoot process
wait $SF_PID
