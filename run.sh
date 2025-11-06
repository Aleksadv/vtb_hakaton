#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 API Security Auditor${NC}"
echo "============================="

BUILD_DIR="./build/classes"
MAIN_CLASS="com.securityscanner.auditor.APISecurityAuditor"

# Check if APISecurityAuditor exists
if [ ! -f "$BUILD_DIR/com/securityscanner/auditor/APISecurityAuditor.class" ]; then
    echo "APISecurityAuditor not found. Please run ./build.sh first"
    exit 1
fi

echo -e "${GREEN}Starting comprehensive API security audit...${NC}"
echo ""

# Run APISecurityAuditor with all arguments
java -cp "$BUILD_DIR" "$MAIN_CLASS" "$@"