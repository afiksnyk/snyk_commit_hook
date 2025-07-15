#!/bin/bash
# scripts/snyk-secrets-simple.sh
# Simple secrets detection - final working version

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Check if Snyk is available
check_snyk() {
    if ! command -v snyk &> /dev/null; then
        print_status $RED "❌ Snyk CLI not found! Install with: npm install -g snyk"
        exit 1
    fi
}

# Check if code files changed
code_files_changed() {
    git diff --cached --name-only | grep -E "\.(js|ts|py|java|rb|go|php|cs|cpp|c|h|jsx|tsx|json|yaml|yml|xml|properties|env|config)$" > /dev/null 2>&1
}

# Main execution
main() {
    print_status $BLUE "🚀 Simple secrets detection..."
    
    # Check prerequisites
    check_snyk
    
    # Check if code files changed
    if ! code_files_changed; then
        print_status $YELLOW "📄 No relevant files changed"
        exit 0
    fi
    
    # Run Snyk Code test
    print_status $BLUE "💻 Scanning code files..."
    print_status $BLUE "Running: snyk code test"
    
    # Capture output directly
    local snyk_output=$(snyk code test 2>&1)
    local snyk_exit_code=$?
    
    # Always check for secrets regardless of exit code
    # (Snyk might return 0 even with issues in some cases)
    local secret_count=$(echo "$snyk_output" | grep -c -i -E "(hardcoded|secret)" || echo "0")
    
    if [ "$secret_count" -gt 0 ]; then
        print_status $RED "❌ Hardcoded secrets detected!"
        echo ""
        
        # Show summary
        local total_issues=$(echo "$snyk_output" | grep -c "✗ \[" || echo "0")
        local high_issues=$(echo "$snyk_output" | grep -c "✗ \[HIGH\]" || echo "0")
        local medium_issues=$(echo "$snyk_output" | grep -c "✗ \[MEDIUM\]" || echo "0")
        local low_issues=$(echo "$snyk_output" | grep -c "✗ \[LOW\]" || echo "0")
        
        print_status $YELLOW "📊 Summary: $total_issues security issue(s) found"
        [ "$high_issues" -gt 0 ] && echo "  • High severity: $high_issues"
        [ "$medium_issues" -gt 0 ] && echo "  • Medium severity: $medium_issues"
        [ "$low_issues" -gt 0 ] && echo "  • Low severity: $low_issues"
        echo ""
        
        # Show detailed secret-related issues
        print_status $BLUE "🔍 Secret-Related Issues:"
        echo "$snyk_output" | grep -i -A3 -B1 -E "(hardcoded|secret)" | \
            grep -E "(✗ \[|Path:|Info:)" | \
            sed 's/^/  /' | \
            head -20
        
        echo ""
        
        # Show affected files
        print_status $BLUE "📁 Affected Files:"
        echo "$snyk_output" | grep "Path:" | sed 's/.*Path: /  • /' | sort -u
        
        echo ""
        print_status $RED "❌ Commit blocked due to hardcoded secrets!"
        print_status $YELLOW "💡 Use environment variables instead of hardcoded values"
        print_status $BLUE "🔧 Run 'snyk code test' for full details"
        exit 1
    else
        print_status $GREEN "✅ No secrets found in scan results"
        print_status $BLUE "🎉 Ready to commit!"
        exit 0
    fi
}

main "$@"
