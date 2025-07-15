#!/bin/bash
# deploy-snyk-hooks.sh
# Full deployment script for Snyk commit hooks

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(pwd)"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
POLICIES_DIR="$PROJECT_ROOT/policies"
REPO_URL="https://github.com/afiksnyk/snyk_commit_hooks.git"

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                           Snyk Commit Hooks                                 ║"
    echo "║                        Full Deployment Script                               ║"
    echo "║                                                                              ║"
    echo "║                    🛡️  Secure Your Code Commits  🛡️                        ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_step() {
    local step=$1
    local message=$2
    echo -e "${BLUE}[STEP $step]${NC} $message"
}

print_substep() {
    local message=$1
    echo -e "${CYAN}  →${NC} $message"
}

check_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macOS"
    elif [[ "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
        DISTRO="Cygwin"
    else
        OS="unknown"
        DISTRO="Unknown"
    fi
    
    print_substep "Detected OS: $DISTRO"
}

check_command() {
    local cmd=$1
    local required=$2
    
    if command -v "$cmd" &> /dev/null; then
        local version=$($cmd --version 2>/dev/null | head -1 || echo "unknown")
        print_status $GREEN "✅ $cmd found ($version)"
        return 0
    else
        if [ "$required" = "required" ]; then
            print_status $RED "❌ $cmd not found (required)"
            return 1
        else
            print_status $YELLOW "⚠️  $cmd not found (optional)"
            return 1
        fi
    fi
}

install_prerequisites() {
    print_step "1" "Installing prerequisites..."
    
    check_os
    
    local missing_required=()
    local missing_optional=()
    
    # Check required tools
    check_command "git" "required" || missing_required+=("git")
    check_command "python3" "required" || missing_required+=("python3")
    check_command "pip3" "required" || missing_required+=("pip3")
    check_command "node" "required" || missing_required+=("node")
    check_command "npm" "required" || missing_required+=("npm")
    
    # Check optional tools
    check_command "snyk" "optional" || missing_optional+=("snyk")
    check_command "jq" "optional" || missing_optional+=("jq")
    check_command "opa" "optional" || missing_optional+=("opa")
    
    # Install missing required tools
    if [ ${#missing_required[@]} -ne 0 ]; then
        print_status $YELLOW "Installing missing required tools: ${missing_required[*]}"
        install_required_tools "${missing_required[@]}"
    fi
    
    # Install missing optional tools
    if [ ${#missing_optional[@]} -ne 0 ]; then
        print_status $YELLOW "Installing missing optional tools: ${missing_optional[*]}"
        install_optional_tools "${missing_optional[@]}"
    fi
    
    echo ""
}

install_required_tools() {
    local tools=("$@")
    
    for tool in "${tools[@]}"; do
        print_substep "Installing $tool..."
        
        case $tool in
            "git")
                if [ "$OS" = "macos" ]; then
                    xcode-select --install 2>/dev/null || true
                elif [ "$OS" = "linux" ]; then
                    sudo apt-get update && sudo apt-get install -y git
                fi
                ;;
            "python3")
                if [ "$OS" = "macos" ]; then
                    brew install python3 || curl https://bootstrap.pypa.io/get-pip.py | python3
                elif [ "$OS" = "linux" ]; then
                    sudo apt-get update && sudo apt-get install -y python3 python3-pip
                fi
                ;;
            "pip3")
                python3 -m ensurepip --upgrade 2>/dev/null || curl https://bootstrap.pypa.io/get-pip.py | python3
                ;;
            "node")
                if [ "$OS" = "macos" ]; then
                    brew install node || {
                        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
                        export NVM_DIR="$HOME/.nvm"
                        [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
                        nvm install node
                    }
                elif [ "$OS" = "linux" ]; then
                    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
                    sudo apt-get install -y nodejs
                fi
                ;;
            "npm")
                # npm usually comes with node
                if ! command -v npm &> /dev/null; then
                    if [ "$OS" = "macos" ]; then
                        brew install npm
                    elif [ "$OS" = "linux" ]; then
                        sudo apt-get install -y npm
                    fi
                fi
                ;;
        esac
    done
}

install_optional_tools() {
    local tools=("$@")
    
    for tool in "${tools[@]}"; do
        print_substep "Installing $tool..."
        
        case $tool in
            "snyk")
                npm install -g snyk
                ;;
            "jq")
                if [ "$OS" = "macos" ]; then
                    brew install jq || {
                        curl -L -o /usr/local/bin/jq https://github.com/stedolan/jq/releases/latest/download/jq-osx-amd64
                        chmod +x /usr/local/bin/jq
                    }
                elif [ "$OS" = "linux" ]; then
                    sudo apt-get update && sudo apt-get install -y jq
                fi
                ;;
            "opa")
                if [ "$OS" = "macos" ]; then
                    brew install opa || {
                        curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_darwin_amd64
                        chmod +x /usr/local/bin/opa
                    }
                elif [ "$OS" = "linux" ]; then
                    curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
                    chmod +x /usr/local/bin/opa
                fi
                ;;
        esac
    done
}

setup_project() {
    print_step "2" "Setting up project..."
    
    # Check if we're in a git repository
    if [ ! -d ".git" ]; then
        print_substep "Initializing git repository..."
        git init
    fi
    
    # Create directory structure
    print_substep "Creating directory structure..."
    mkdir -p "$SCRIPTS_DIR"
    mkdir -p "$POLICIES_DIR"
    
    # Check if this is a fresh clone or existing setup
    if [ -f ".pre-commit-config.yaml" ] || [ -f "pre-commit-config.yaml" ]; then
        print_substep "Pre-commit configuration found"
    else
        print_substep "This appears to be a fresh setup"
    fi
    
    echo ""
}

install_precommit() {
    print_step "3" "Installing pre-commit framework..."
    
    # Install pre-commit
    print_substep "Installing pre-commit via pip..."
    pip3 install pre-commit
    
    # Verify installation
    if command -v pre-commit &> /dev/null; then
        local version=$(pre-commit --version)
        print_status $GREEN "✅ pre-commit installed: $version"
    else
        print_status $RED "❌ Failed to install pre-commit"
        exit 1
    fi
    
    echo ""
}

create_scripts() {
    print_step "4" "Creating detection scripts..."
    
    # Create simple detection script
    print_substep "Creating simple detection script..."
    cat > "$SCRIPTS_DIR/snyk-secrets-simple.sh" << 'SCRIPT_EOF'
#!/bin/bash
# Simple secrets detection script - no jq dependency

set -e

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

check_snyk() {
    if ! command -v snyk &> /dev/null; then
        print_status $RED "❌ Snyk CLI not found! Install with: npm install -g snyk"
        exit 1
    fi
}

code_files_changed() {
    git diff --cached --name-only | grep -E "\.(js|ts|py|java|rb|go|php|cs|cpp|c|h|jsx|tsx|json|yaml|yml|xml|properties|env|config)$" > /dev/null 2>&1
}

main() {
    print_status $BLUE "🚀 Simple secrets detection..."
    
    check_snyk
    
    if ! code_files_changed; then
        print_status $YELLOW "📄 No relevant files changed"
        exit 0
    fi
    
    print_status $BLUE "💻 Scanning code files..."
    
    local snyk_output=$(snyk code test 2>&1)
    local secret_count=$(echo "$snyk_output" | grep -c -i -E "(hardcoded|secret)" || echo "0")
    
    if [ "$secret_count" -gt 0 ]; then
        print_status $RED "❌ Hardcoded secrets detected!"
        echo ""
        
        local total_issues=$(echo "$snyk_output" | grep -c "✗ \[" || echo "0")
        local high_issues=$(echo "$snyk_output" | grep -c "✗ \[HIGH\]" || echo "0")
        local medium_issues=$(echo "$snyk_output" | grep -c "✗ \[MEDIUM\]" || echo "0")
        
        print_status $YELLOW "📊 Summary: $total_issues security issue(s) found"
        [ "$high_issues" -gt 0 ] && echo "  • High severity: $high_issues"
        [ "$medium_issues" -gt 0 ] && echo "  • Medium severity: $medium_issues"
        echo ""
        
        print_status $BLUE "🔍 Secret-Related Issues:"
        echo "$snyk_output" | grep -i -A3 -B1 -E "(hardcoded|secret)" | \
            grep -E "(✗ \[|Path:|Info:)" | \
            sed 's/^/  /' | \
            head -20
        
        echo ""
        print_status $RED "❌ Commit blocked due to hardcoded secrets!"
        print_status $YELLOW "💡 Use environment variables instead of hardcoded values"
        exit 1
    else
        print_status $GREEN "✅ No secrets found"
        exit 0
    fi
}

main "$@"
SCRIPT_EOF

    # Create OPA detection script with jq fallback
    print_substep "Creating OPA detection script..."
    cat > "$SCRIPTS_DIR/snyk-secrets-opa-check.sh" << 'SCRIPT_EOF'
#!/bin/bash
# OPA-based secrets detection script with fallback

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

RESULTS_FILE="snyk-code-results.json"
POLICY_FILE="policies/secrets_only_policy.rego"
OPA_INPUT_FILE="opa-input.json"
OPA_OUTPUT_FILE="opa-output.json"

print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

check_prerequisites() {
    local has_opa=false
    local has_jq=false
    
    if ! command -v snyk &> /dev/null; then
        print_status $RED "❌ Snyk CLI not found! Install with: npm install -g snyk"
        exit 1
    fi
    
    if command -v opa &> /dev/null; then
        has_opa=true
    fi
    
    if command -v jq &> /dev/null; then
        has_jq=true
    fi
    
    if [ "$has_opa" = true ] && [ "$has_jq" = true ] && [ -f "$POLICY_FILE" ]; then
        return 0  # Full OPA mode
    else
        print_status $YELLOW "⚠️  OPA/jq not available, using simple detection"
        return 1  # Fallback mode
    fi
}

code_files_changed() {
    git diff --cached --name-only | grep -E "\.(js|ts|py|java|rb|go|php|cs|cpp|c|h|jsx|tsx|json|yaml|yml|xml|properties|env|config)$" > /dev/null 2>&1
}

simple_secret_check() {
    local snyk_output=$1
    
    if echo "$snyk_output" | grep -q -i -E "(hardcoded|secret)"; then
        print_status $RED "❌ Hardcoded secrets detected!"
        echo ""
        print_status $BLUE "🔍 Issues found:"
        echo "$snyk_output" | grep -i -A2 -B1 -E "(hardcoded|secret)" | head -10 | sed 's/^/  /'
        return 1
    fi
    
    return 0
}

cleanup() {
    rm -f "$RESULTS_FILE" "$OPA_INPUT_FILE" "$OPA_OUTPUT_FILE"
}

trap cleanup EXIT

main() {
    print_status $BLUE "🚀 OPA secrets detection..."
    
    if ! code_files_changed; then
        print_status $YELLOW "📄 No relevant files changed"
        exit 0
    fi
    
    print_status $BLUE "💻 Scanning code files..."
    
    local snyk_output=$(snyk code test 2>&1)
    
    # Check if we can use full OPA mode
    if check_prerequisites; then
        print_status $BLUE "🔍 Running OPA policy evaluation..."
        
        # Try OPA evaluation
        local snyk_json_output=$(snyk code test --json 2>&1)
        echo "$snyk_json_output" > "$RESULTS_FILE"
        
        if jq empty "$RESULTS_FILE" 2>/dev/null && jq -e '.vulnerabilities' "$RESULTS_FILE" >/dev/null 2>&1; then
            # Convert to SARIF format
            jq '{
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
            }' "$RESULTS_FILE" > "${RESULTS_FILE}.sarif" 2>/dev/null
            
            # Create OPA input
            jq -n \
                --argjson snyk_results "$(cat "${RESULTS_FILE}.sarif")" \
                --arg git_branch "$(git branch --show-current 2>/dev/null || echo 'unknown')" \
                '{
                    runs: $snyk_results.runs,
                    git_branch: $git_branch,
                    timestamp: now
                }' > "$OPA_INPUT_FILE"
            
            # Evaluate with OPA
            if opa eval -d "$POLICY_FILE" -I "$OPA_INPUT_FILE" -f pretty "data.snyk.security.secrets" > "$OPA_OUTPUT_FILE" 2>/dev/null; then
                local allow_commit=$(cat "$OPA_OUTPUT_FILE" | jq -r '.allow // false')
                
                if [ "$allow_commit" = "false" ]; then
                    print_status $RED "❌ OPA policy blocked commit!"
                    exit 1
                else
                    print_status $GREEN "✅ OPA policy allows commit"
                    exit 0
                fi
            fi
        fi
    fi
    
    # Fallback to simple check
    print_status $BLUE "🔍 Using simple detection fallback..."
    if ! simple_secret_check "$snyk_output"; then
        print_status $RED "❌ Commit blocked due to hardcoded secrets!"
        exit 1
    fi
    
    print_status $GREEN "✅ No secrets found"
}

main "$@"
SCRIPT_EOF

    # Make scripts executable
    chmod +x "$SCRIPTS_DIR/snyk-secrets-simple.sh"
    chmod +x "$SCRIPTS_DIR/snyk-secrets-opa-check.sh"
    
    print_status $GREEN "✅ Detection scripts created"
    echo ""
}

create_opa_policy() {
    print_step "5" "Creating OPA policy..."
    
    print_substep "Creating secrets detection policy..."
    cat > "$POLICIES_DIR/secrets_only_policy.rego" << 'POLICY_EOF'
# OPA policy for detecting hardcoded secrets
package snyk.security.secrets

import rego.v1

default allow := true

allow := false if {
    count(secret_violations) > 0
}

secret_violations contains violation if {
    some result in input.runs[0].results
    violation := create_violation(result)
    is_secret_violation(violation)
}

create_violation(result) := violation if {
    violation := {
        "rule_id": result.ruleId,
        "message": result.message.text,
        "severity": result.level,
        "file": result.locations[0].physicalLocation.artifactLocation.uri,
        "line": result.locations[0].physicalLocation.region.startLine,
        "secret_type": classify_secret_type(result.message.text)
    }
}

classify_secret_type(message) := secret_type if {
    contains(lower(message), "password")
    secret_type := "password"
} else := secret_type if {
    contains(lower(message), "secret")
    secret_type := "generic_secret"
} else := secret_type if {
    contains(lower(message), "token")
    secret_type := "token"
} else := secret_type if {
    contains(lower(message), "key")
    secret_type := "api_key"
} else := "unknown"

is_secret_violation(violation) if {
    some keyword in secret_keywords
    contains(lower(violation.message), keyword)
}

secret_keywords := {
    "hardcoded",
    "hard-coded",
    "secret",
    "password",
    "api key",
    "token",
    "credential"
}

violation_report := {
    "blocked": count(secret_violations) > 0,
    "total_secret_violations": count(secret_violations),
    "secret_violations": secret_violations,
    "secrets_by_type": {type: count([v | v := secret_violations[_]; v.secret_type == type]) |
        some type in {v.secret_type | v := secret_violations[_]}
    }
}
POLICY_EOF

    print_status $GREEN "✅ OPA policy created"
    echo ""
}

create_precommit_config() {
    print_step "6" "Creating pre-commit configuration..."
    
    print_substep "Creating .pre-commit-config.yaml..."
    cat > "$PROJECT_ROOT/.pre-commit-config.yaml" << 'CONFIG_EOF'
# .pre-commit-config.yaml
# Snyk secrets detection with OPA and Simple approaches

repos:
  - repo: local
    hooks:
      # OPA-based secrets detection (with fallback)
      - id: snyk-secrets-opa
        name: Detect Hardcoded Secrets (OPA)
        entry: bash scripts/snyk-secrets-opa-check.sh
        language: system
        pass_filenames: false
        stages: [pre-commit]
        files: \.(js|ts|py|java|rb|go|php|cs|cpp|c|h|jsx|tsx|json|yaml|yml|xml|properties|env|config)$
        
      # Simple text-based secrets detection
      - id: snyk-secrets-simple
        name: Detect Hardcoded Secrets (Simple)
        entry: bash scripts/snyk-secrets-simple.sh
        language: system
        pass_filenames: false
        stages: [pre-commit]
        files: \.(js|ts|py|java|rb|go|php|cs|cpp|c|h|jsx|tsx|json|yaml|yml|xml|properties|env|config)$
CONFIG_EOF

    print_status $GREEN "✅ Pre-commit configuration created"
    echo ""
}

install_hooks() {
    print_step "7" "Installing pre-commit hooks..."
    
    print_substep "Installing hooks..."
    if pre-commit install; then
        print_status $GREEN "✅ Pre-commit hooks installed"
    else
        print_status $RED "❌ Failed to install pre-commit hooks"
        exit 1
    fi
    
    echo ""
}

create_gitignore() {
    print_step "8" "Creating .gitignore..."
    
    if [ ! -f ".gitignore" ]; then
        cat > ".gitignore" << 'GITIGNORE_EOF'
# Snyk temporary files
snyk-code-results.json
snyk-code-results.json.sarif
opa-input.json
opa-output.json
snyk-secrets-simple.json

# Test files with secrets
test-secrets.*
**/test-secrets.*

# Code directory (if exists)
code/
GITIGNORE_EOF
        print_status $GREEN "✅ .gitignore created"
    else
        print_status $YELLOW "⚠️  .gitignore already exists, skipping"
    fi
    
    echo ""
}

authenticate_snyk() {
    print_step "9" "Authenticating with Snyk..."
    
    if command -v snyk &> /dev/null; then
        print_substep "Checking Snyk authentication..."
        if snyk auth check &> /dev/null; then
            print_status $GREEN "✅ Snyk already authenticated"
        else
            print_status $YELLOW "⚠️  Snyk not authenticated"
            print_status $BLUE "Please run: snyk auth"
            echo ""
            read -p "Would you like to authenticate now? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                snyk auth
            fi
        fi
    else
        print_status $RED "❌ Snyk CLI not found"
    fi
    
    echo ""
}

run_tests() {
    print_step "10" "Running tests..."
    
    print_substep "Creating test file with secrets..."
    cat > test_secrets_sample.js << 'TEST_EOF'
// Test file with hardcoded secrets
const API_KEY = "sk-1234567890abcdef";
const password = "admin123";
const token = "ghp_1234567890abcdef";
TEST_EOF

    print_substep "Testing pre-commit hooks..."
    git add test_secrets_sample.js
    
    if pre-commit run --files test_secrets_sample.js; then
        print_status $YELLOW "⚠️  Test passed unexpectedly - this might indicate an issue"
    else
        print_status $GREEN "✅ Test correctly detected secrets and blocked commit!"
    fi
    
    # Clean up
    git reset HEAD test_secrets_sample.js 2>/dev/null || true
    rm -f test_secrets_sample.js
    
    echo ""
}

create_documentation() {
    print_step "11" "Creating documentation..."
    
    print_substep "Creating README.md..."
    cat > "README.md" << 'README_EOF'
# Snyk Commit Hooks

Automated detection of hardcoded secrets in your code using Snyk Code analysis.

## Quick Start

1. **Install dependencies:**
   ```bash
   npm install -g snyk
   pip install pre-commit
   ```

2. **Authenticate with Snyk:**
   ```bash
   snyk auth
   ```

3. **The hooks are already installed and ready to use!**

## How It Works

- **Simple Detection**: Fast text-based pattern matching
- **OPA Detection**: Advanced policy-based analysis (requires jq and opa)
- **Automatic Fallback**: OPA script falls back to simple detection if dependencies are missing

## Usage

Hooks run automatically on commit. To test manually:
```bash
# Test simple detection
./scripts/snyk-secrets-simple.sh

# Test OPA detection
./scripts/snyk-secrets-opa-check.sh
```

## Troubleshooting

- **"Snyk not found"**: Run `npm install -g snyk`
- **"Not authenticated"**: Run `snyk auth`
- **Skip hooks**: Use `git commit --no-verify` for emergencies

## Files

- `scripts/snyk-secrets-simple.sh` - Simple detection (no dependencies)
- `scripts/snyk-secrets-opa-check.sh` - OPA detection (with fallback)
- `policies/secrets_only_policy.rego` - OPA policy rules
- `.pre-commit-config.yaml` - Pre-commit configuration

Made with ❤️ for secure coding practices
README_EOF

    print_status $GREEN "✅ Documentation created"
    echo ""
}

print_summary() {
    print_step "12" "Deployment Summary"
    
    echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
    echo ""
    
    echo -e "${BLUE}📋 What was installed:${NC}"
    echo "  ✅ Pre-commit framework"
    echo "  ✅ Snyk secrets detection scripts"
    echo "  ✅ OPA policy for advanced detection"
    echo "  ✅ Pre-commit configuration"
    echo "  ✅ Documentation and .gitignore"
    echo ""
    
    echo -e "${BLUE}🔧 Dependencies:${NC}"
    echo "  • Required: git, python3, node.js, npm, snyk"
    echo "  • Optional: jq, opa (for advanced OPA detection)"
    echo ""
    
    echo -e "${BLUE}🚀 Next steps:${NC}"
    echo "  1. Ensure Snyk is authenticated: ${YELLOW}snyk auth${NC}"
    echo "  2. Test the setup: ${YELLOW}git commit -m 'test'${NC}"
    echo "  3. Read the documentation: ${YELLOW}cat README.md${NC}"
    echo ""
    
    echo -e "${BLUE}💡 Key Features:${NC}"
    echo "  • Dual detection: Simple (fast) + OPA (advanced)"
    echo "  • Automatic fallback if optional dependencies missing"
    echo "  • No jq dependency for basic functionality"
    echo "  • Works on macOS, Linux, and Windows"
    echo ""
    
    echo -e "${CYAN}Happy secure coding! 🛡️${NC}"
}

main() {
    print_banner
    
    install_prerequisites
    setup_project
    install_precommit
    create_scripts
    create_opa_policy
    create_precommit_config
    install_hooks
    create_gitignore
    authenticate_snyk
    run_tests
    create_documentation
    print_summary
}

# Allow script to be sourced or run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
