#!/bin/bash
# scripts/snyk-secrets-opa-check.sh
# OPA secrets detection - final working version

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
RESULTS_FILE=${SNYK_RESULTS_FILE:-"snyk-code-results.json"}
POLICY_FILE=${OPA_POLICY_FILE:-"policies/secrets_only_policy.rego"}
OPA_INPUT_FILE=${OPA_INPUT_FILE:-"opa-input.json"}
OPA_OUTPUT_FILE=${OPA_OUTPUT_FILE:-"opa-output.json"}

print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_config() {
    print_status $BLUE "🔐 Secrets Detection Configuration:"
    echo "  • Policy: Hardcoded secrets only"
    echo "  • Git branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    local missing_tools=()
    
    if ! command -v snyk &> /dev/null; then
        missing_tools+=("snyk")
    fi
    
    if ! command -v opa &> /dev/null; then
        missing_tools+=("opa")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_status $RED "❌ Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    if [ ! -f "$POLICY_FILE" ]; then
        print_status $RED "❌ Policy file not found: $POLICY_FILE"
        exit 1
    fi
}

# Check if any code files have changed
code_files_changed() {
    git diff --cached --name-only | grep -E "\.(js|ts|py|java|rb|go|php|cs|cpp|c|h|jsx|tsx|json|yaml|yml|xml|properties|env|config)$" > /dev/null 2>&1
}

# Simple fallback check using text matching
simple_secret_check() {
    local snyk_output=$1
    
    # Check for secret-related text in output
    if echo "$snyk_output" | grep -q -i -E "(hardcoded|secret)"; then
        print_status $RED "❌ Hardcoded secrets detected! (Simple check)"
        echo ""
        print_status $BLUE "🔍 Issues found:"
        echo "$snyk_output" | grep -i -A2 -B1 -E "(hardcoded|secret)" | head -10 | sed 's/^/  /'
        return 1
    fi
    
    return 0
}

# Create OPA input
create_opa_input() {
    local snyk_results_file=$1
    local git_branch=$(git branch --show-current 2>/dev/null || echo "unknown")
    local changed_files=$(git diff --cached --name-only | jq -R . | jq -s .)
    
    jq -n \
        --argjson snyk_results "$(cat "$snyk_results_file")" \
        --arg git_branch "$git_branch" \
        --argjson changed_files "$changed_files" \
        '{
            runs: $snyk_results.runs,
            git_branch: $git_branch,
            changed_files: $changed_files,
            timestamp: now
        }' > "$OPA_INPUT_FILE"
}

# Evaluate secrets policy with OPA
evaluate_secrets_policy() {
    local input_file=$1
    
    print_status $BLUE "🔍 Scanning for hardcoded secrets..."
    
    if ! opa eval -d "$POLICY_FILE" -I "$input_file" -f pretty "data.snyk.security.secrets" > "$OPA_OUTPUT_FILE" 2>/dev/null; then
        print_status $RED "❌ OPA policy evaluation failed!"
        return 1
    fi
    
    local allow_commit=$(cat "$OPA_OUTPUT_FILE" | jq -r '.allow // false')
    local violation_report=$(cat "$OPA_OUTPUT_FILE" | jq -r '.violation_report // {}')
    
    if [ "$allow_commit" = "true" ]; then
        print_status $GREEN "✅ No hardcoded secrets detected!"
        return 0
    else
        print_status $RED "❌ Hardcoded secrets detected!"
        
        # Show secrets summary
        local total_secrets=$(echo "$violation_report" | jq -r '.total_secret_violations // 0')
        if [ "$total_secrets" -gt 0 ]; then
            print_status $PURPLE "🔐 Secret Violations Found: $total_secrets"
            
            # Show secrets by type
            print_status $BLUE "📊 Secrets by Type:"
            echo "$violation_report" | jq -r '.secrets_by_type // {} | to_entries[] | "  • \(.key): \(.value)"'
            
            # Show secrets by severity
            print_status $BLUE "⚠️  Secrets by Severity:"
            echo "$violation_report" | jq -r '.secrets_by_severity // {} | to_entries[] | "  • \(.key): \(.value)"'
            
            # Show affected files
            print_status $BLUE "📁 Affected Files:"
            echo "$violation_report" | jq -r '.affected_files[]? | "  • \(.)"'
            
            echo ""
            print_status $PURPLE "🔍 Detailed Secret Violations:"
            echo "$violation_report" | jq -r '.secret_violations[]? | 
                "  • \(.secret_type | ascii_upcase): \(.message)
                    File: \(.file):\(.line)
                    Rule: \(.rule_id)
                    Severity: \(.severity)
                "'
        fi
        
        return 1
    fi
}

# Cleanup temporary files
cleanup() {
    rm -f "$RESULTS_FILE" "$OPA_INPUT_FILE" "$OPA_OUTPUT_FILE"
}

# Set up cleanup trap
trap cleanup EXIT

# Main execution
main() {
    print_status $BLUE "🚀 Starting secrets detection scan..."
    
    print_config
    check_prerequisites
    
    # Check if code files changed
    if ! code_files_changed; then
        print_status $YELLOW "📄 No relevant files changed, skipping secrets scan"
        exit 0
    fi
    
    print_status $BLUE "💻 Code files changed, scanning for secrets..."
    
    # Run Snyk Code test
    print_status $BLUE "Running: snyk code test"
    
    local snyk_output=$(snyk code test 2>&1)
    local snyk_exit_code=$?
    
    # First, try simple text-based check as fallback
    if ! simple_secret_check "$snyk_output"; then
        print_status $RED "❌ Commit blocked due to hardcoded secrets!"
        print_status $BLUE "💡 Remove the hardcoded secrets and try again"
        print_status $YELLOW "🔧 Consider using environment variables, config files, or secret management tools"
        exit 1
    fi
    
    # Try JSON-based OPA check if available
    local snyk_json_output=$(snyk code test --json 2>&1)
    echo "$snyk_json_output" > "$RESULTS_FILE"
    
    # Check if JSON is valid and has vulnerabilities
    if jq empty "$RESULTS_FILE" 2>/dev/null && jq -e '.vulnerabilities' "$RESULTS_FILE" >/dev/null 2>&1; then
        # Convert JSON to SARIF-like format for OPA policy
        if jq '{
            runs: [{
                results: [
                    .vulnerabilities[]? | {
                        ruleId: .id,
                        message: {text: .title},
                        level: (if .severity == "high" then "error" elif .severity == "medium" then "warning" else "note" end),
                        locations: [{
                            physicalLocation: {
                                artifactLocation: {uri: .filePath},
                                region: {startLine: .lineNumber}
                            }
                        }]
                    }
                ]
            }]
        }' "$RESULTS_FILE" > "${RESULTS_FILE}.sarif" 2>/dev/null; then
            
            # Create OPA input and evaluate
            create_opa_input "${RESULTS_FILE}.sarif"
            
            if ! evaluate_secrets_policy "$OPA_INPUT_FILE"; then
                print_status $RED "❌ Commit blocked due to hardcoded secrets!"
                print_status $BLUE "💡 Remove the hardcoded secrets and try again"
                print_status $YELLOW "🔧 Consider using environment variables, config files, or secret management tools"
                exit 1
            fi
        fi
    fi
    
    # If we reach here, no secrets were found
    print_status $GREEN "✅ No secrets found - commit allowed!"
    print_status $BLUE "🎉 Ready to commit!"
}

# Run main function
main "$@"
