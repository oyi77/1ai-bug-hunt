#!/bin/bash
# Bug Bounty Scheduler - Cron Setup
# Sets up automated bug bounty hunting on a schedule

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEDULER_DIR="$SCRIPT_DIR"
LOG_DIR="$SCHEDULER_DIR/../logs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Bug Bounty Scheduler Setup ===${NC}"
echo ""

# Check dependencies
echo "[*] Checking dependencies..."
for cmd in python3 subfinder httpx nuclei nmap ffuf curl; do
    if command -v $cmd &>/dev/null; then
        echo -e "  [${GREEN}OK${NC}] $cmd"
    else
        echo -e "  [${RED}MISSING${NC}] $cmd"
    fi
done

# Check Python deps
echo ""
echo "[*] Checking Python dependencies..."
python3 -c "import requests" 2>/dev/null && echo -e "  [${GREEN}OK${NC}] requests" || {
    echo -e "  [${YELLOW}Installing${NC}] requests..."
    pip3 install requests
}

# Check .env
echo ""
if [ -f "$SCHEDULER_DIR/../.env" ]; then
    echo -e "  [${GREEN}OK${NC}] .env file exists"
else
    echo -e "  [${RED}MISSING${NC}] .env file"
    echo "  Create .env with your credentials first!"
    exit 1
fi

# Make scripts executable
chmod +x "$SCHEDULER_DIR/discover.py"
chmod +x "$SCHEDULER_DIR/recon.py"
chmod +x "$SCHEDULER_DIR/hunt.py"
chmod +x "$SCHEDULER_DIR/report.py"
chmod +x "$SCHEDULER_DIR/run.py"

echo ""
echo -e "${GREEN}=== Cron Schedule Options ===${NC}"
echo ""
echo "  1) Every 6 hours (recommended)"
echo "  2) Every 12 hours"
echo "  3) Every 24 hours (daily)"
echo "  4) Custom cron expression"
echo "  5) Remove existing cron job"
echo ""

read -p "Select option [1-5]: " choice

# Remove existing cron job first
crontab -l 2>/dev/null | grep -v "bugbounty/scheduler/run.py" | crontab - 2>/dev/null

case $choice in
    1)
        CRON="0 */6 * * *"
        DESC="every 6 hours"
        ;;
    2)
        CRON="0 */12 * * *"
        DESC="every 12 hours"
        ;;
    3)
        CRON="0 2 * * *"
        DESC="daily at 2 AM"
        ;;
    4)
        read -p "Enter cron expression: " CRON
        DESC="custom: $CRON"
        ;;
    5)
        echo -e "${GREEN}Cron job removed.${NC}"
        exit 0
        ;;
    *)
        echo "Invalid option"
        exit 1
        ;;
esac

# Add cron job
CRON_CMD="$CRON cd $SCHEDULER_DIR && /usr/bin/python3 run.py --force >> $LOG_DIR/cron.log 2>&1"

(crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -

echo ""
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo ""
echo "Cron job added: $DESC"
echo "Command: $CRON_CMD"
echo ""
echo "Log file: $LOG_DIR/cron.log"
echo ""
echo "Manual run:"
echo "  cd $SCHEDULER_DIR && python3 run.py --force"
echo ""
echo "Check status:"
echo "  cd $SCHEDULER_DIR && python3 run.py --status"
echo ""
echo "List cron jobs:"
echo "  crontab -l"
echo ""

# Test run option
read -p "Run test now? (y/n): " test_run
if [ "$test_run" = "y" ] || [ "$test_run" = "Y" ]; then
    echo ""
    echo -e "${YELLOW}Starting test run...${NC}"
    cd "$SCHEDULER_DIR"
    python3 run.py --force --dry-run --max-targets 1
fi
