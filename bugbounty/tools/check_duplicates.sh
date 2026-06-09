#!/bin/bash
# check_duplicates.sh — Check for duplicate findings before submission
# Usage: ./check_duplicates.sh <target> <vulnerability_type>

TARGET=$1
VULN_TYPE=$2

if [ -z "$TARGET" ] || [ -z "$VULN_TYPE" ]; then
    echo "Usage: $0 <target> <vulnerability_type>"
    echo "Example: $0 mokapos.com 'swagger exposure'"
    exit 1
fi

echo "=== Checking for duplicates: $TARGET — $VULN_TYPE ==="

# 1. Search disclosed reports on Bugcrowd
echo ""
echo "--- Bugcrowd Disclosed Reports ---"
curl -s "https://bugcrowd.com/engagements?search=$TARGET" \
  -H "User-Agent: Mozilla/5.0" \
  --connect-timeout 10 2>/dev/null | grep -i "disclosed\|public" | head -5

# 2. Search YesWeHack disclosed reports
echo ""
echo "--- YesWeHack Disclosed Reports ---"
curl -s "https://api.yeswehack.com/programs?search=$TARGET" \
  --connect-timeout 10 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for item in data.get('items', []):
        print(f\"  - {item.get('title')} ({item.get('slug')})\")
except:
    print('  No results')
" 2>/dev/null

# 3. Search CVE databases
echo ""
echo "--- CVE Search ---"
curl -s "https://cve.circl.lu/api/search/$TARGET" \
  --connect-timeout 10 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for cve in data[:5]:
        print(f\"  - {cve.get('id')}: {cve.get('summary', '')[:100]}\")
except:
    print('  No CVEs found')
" 2>/dev/null

# 4. Search Google for existing reports
echo ""
echo "--- Google Search ---"
echo "  Manual check: site:bugcrowd.com \"$TARGET\" \"$VULN_TYPE\""
echo "  Manual check: site:hackerone.com \"$TARGET\" \"$VULN_TYPE\""
echo "  Manual check: site:yeswehack.com \"$TARGET\" \"$VULN_TYPE\""

# 5. Check if endpoint is documented
echo ""
echo "--- Documentation Check ---"
echo "  Check: https://$TARGET/docs"
echo "  Check: https://$TARGET/api-docs"
echo "  Check: https://$TARGET/swagger.json"

echo ""
echo "=== Duplicate check complete ==="
echo "If no duplicates found, proceed with submission."
