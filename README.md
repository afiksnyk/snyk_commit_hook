# Snyk Commit Hooks

A comprehensive pre-commit hook system for detecting hardcoded secrets in your code using Snyk Code analysis with both simple text-based detection and advanced OPA (Open Policy Agent) policy evaluation.

## 🚀 Quick Start

### One-Command Deployment

The easiest way to get started is using our deployment script:

```bash
# Clone the repository
git clone https://github.com/afiksnyk/snyk_commit_hooks.git
cd snyk_commit_hooks

# Make deployment script executable
chmod +x deploy-snyk-hooks.sh

# Run deployment (installs everything automatically)
./deploy-snyk-hooks.sh
```

That's it! The deployment script will:
- ✅ **Auto-detect your OS** (macOS, Linux, Windows)
- ✅ **Install all dependencies** (git, python3, node.js, npm, snyk, pre-commit)
- ✅ **Install optional tools** (jq, opa) if possible
- ✅ **Create all necessary files** (scripts, policies, configs)
- ✅ **Set up pre-commit hooks** automatically
- ✅ **Test the installation** to ensure everything works
- ✅ **Authenticate with Snyk** (with prompts)

### Manual Installation (Alternative)

If you prefer manual setup or the deployment script doesn't work:

<details>
<summary>Click to expand manual installation steps</summary>

#### Prerequisites

- **Git** (obviously!)
- **Python 3** and **pip**
- **Node.js** and **npm**
- **Snyk CLI**: `npm install -g snyk`
- **jq** (optional): `brew install jq` (macOS) or `apt install jq` (Linux)
- **OPA** (optional): Download from [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa)

#### Manual Setup Steps

1. **Install pre-commit:**
   ```bash
   pip install pre-commit
   ```

2. **Configure pre-commit:**
   ```bash
   # Install the hooks
   pre-commit install
   ```

3. **Authenticate with Snyk:**
   ```bash
   snyk auth
   ```

4. **Make scripts executable:**
   ```bash
   chmod +x scripts/snyk-secrets-simple.sh
   chmod +x scripts/snyk-secrets-opa-check.sh
   ```

</details>

## 🔧 How It Works

### Automatic Fallback System

The system intelligently adapts to your environment:

- **🎯 Simple Detection (`snyk-secrets-simple.sh`)**
  - Uses basic `snyk code test` + text pattern matching
  - **No dependencies** beyond Snyk CLI
  - Fast and reliable

- **🧠 OPA Detection (`snyk-secrets-opa-check.sh`)**
  - Advanced policy-based detection using OPA
  - **Automatically falls back** to simple detection if jq/opa unavailable
  - Provides detailed categorization when full dependencies present

### Supported File Types

The hooks scan these file types for secrets:
- **Languages**: `.js`, `.ts`, `.py`, `.java`, `.go`, `.php`, `.rb`, `.cs`, `.cpp`, `.c`, `.h`
- **Config files**: `.json`, `.yaml`, `.yml`, `.xml`, `.properties`, `.env`, `.config`

## 🛡️ What Gets Detected

The system will block commits containing:

- **🔑 Hardcoded passwords**: `password = "secret123"`
- **🔐 API keys**: `api_key = "sk-1234567890abcdef"`
- **🎫 Authentication tokens**: `token = "ghp_1234567890abcdef"`
- **🗄️ Database credentials**: `db_password = "admin123"`
- **🔒 OAuth secrets**: `client_secret = "oauth_secret_123"`
- **☁️ Cloud provider keys**: AWS access keys, Azure secrets, GCP keys
- **💳 Service credentials**: Stripe keys, SendGrid tokens, Twilio auth tokens

## 🧪 Testing

After deployment, test the system:

```bash
# Test simple detection
./scripts/snyk-secrets-simple.sh

# Test OPA detection (with fallback)
./scripts/snyk-secrets-opa-check.sh

# Run all pre-commit hooks
pre-commit run --all-files

# Create a test file with secrets
echo 'const API_KEY = "sk-1234567890abcdef";' > test-secrets.js
git add test-secrets.js
git commit -m "test secrets detection"  # Should be blocked!
```

## 📋 Output Examples

### ✅ Successful Scan
```
🚀 Simple secrets detection...
💻 Scanning code files...
✅ No secrets found
```

### ❌ Blocked Commit
```
❌ Hardcoded secrets detected!

📊 Summary: 3 security issue(s) found
  • High severity: 2
  • Medium severity: 1

🔍 Secret-Related Issues:
  ✗ [HIGH] Hardcoded Secret
  Path: auth-service.js, line 11
  Info: Avoid hardcoding values that are meant to be secret...

❌ Commit blocked due to hardcoded secrets!
💡 Use environment variables instead of hardcoded values
```

## 🔧 Customization

### Modify Detection Rules

Edit `policies/secrets_only_policy.rego` to customize OPA detection:

```rego
# Add new secret keywords
secret_keywords := {
    "hardcoded",
    "secret",
    "password",
    "your_custom_keyword"  # Add your own
}
```

### Skip Hooks When Needed

```bash
# Skip all hooks for emergency commits
git commit --no-verify -m "emergency fix"

# Skip specific hooks
SKIP=snyk-secrets-opa git commit -m "skip only OPA hook"

# Skip both secret detection hooks
SKIP=snyk-secrets-opa,snyk-secrets-simple git commit -m "skip both hooks"
```

## 🛠️ Troubleshooting

### Common Issues

1. **"Snyk not found"**
   ```bash
   npm install -g snyk
   snyk auth
   ```

2. **"jq not found" (but OPA script still works)**
   ```bash
   # Optional - OPA script automatically falls back to simple detection
   brew install jq  # macOS
   apt install jq   # Linux
   ```

3. **"Pre-commit hooks not running"**
   ```bash
   pre-commit install
   ```

4. **"Permission denied"**
   ```bash
   chmod +x scripts/snyk-secrets-simple.sh
   chmod +x scripts/snyk-secrets-opa-check.sh
   ```

### Debug Mode

Run scripts manually to see detailed output:
```bash
./scripts/snyk-secrets-simple.sh
./scripts/snyk-secrets-opa-check.sh
```

### Re-run Deployment

If something goes wrong, you can re-run the deployment:
```bash
./deploy-snyk-hooks.sh
```

## 📁 Project Structure

After deployment, you'll have:

```
├── deploy-snyk-hooks.sh           # Deployment script
├── .pre-commit-config.yaml        # Pre-commit configuration
├── .gitignore                     # Git ignore rules
├── README.md                      # This file
├── scripts/
│   ├── snyk-secrets-simple.sh     # Simple detection (no dependencies)
│   └── snyk-secrets-opa-check.sh  # OPA detection (with fallback)
└── policies/
    └── secrets_only_policy.rego   # OPA policy rules
```

## 🌟 Key Features

- **🚀 One-command deployment** - Full setup in seconds
- **🔄 Automatic fallback** - Works even if optional dependencies fail
- **🎯 Dual detection** - Simple (fast) + OPA (advanced)
- **🌍 Cross-platform** - macOS, Linux, Windows support
- **📦 Auto-installs dependencies** - No manual setup required
- **🧪 Built-in testing** - Validates installation automatically
- **📖 Self-documenting** - Creates its own documentation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Test with the deployment script
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🔗 Related Links

- [Snyk Code Documentation](https://docs.snyk.io/snyk-code)
- [Open Policy Agent](https://www.openpolicyagent.org/)
- [Pre-commit Framework](https://pre-commit.com/)

---

**Made with ❤️ for secure coding practices**

*Get started in 30 seconds: `./deploy-snyk-hooks.sh`* 🚀

## 🔧 Configuration

### Pre-commit Configuration

The `.pre-commit-config.yaml` file contains two hooks:

- **`snyk-secrets-opa`**: Advanced policy-based detection using OPA
- **`snyk-secrets-simple`**: Lightweight text-based detection

Both hooks will run on every commit and block if hardcoded secrets are detected.

### Supported File Types

The hooks scan these file types for secrets:
- JavaScript/TypeScript: `.js`, `.ts`, `.jsx`, `.tsx`
- Python: `.py`
- Java: `.java`
- Go: `.go`
- PHP: `.php`
- C/C++: `.c`, `.cpp`, `.h`
- Ruby: `.rb`
- C#: `.cs`
- Configuration files: `.json`, `.yaml`, `.yml`, `.xml`, `.properties`, `.env`, `.config`

## 🛡️ How It Works

### Simple Detection (`snyk-secrets-simple.sh`)
- Runs `snyk code test` to analyze your code
- Uses text pattern matching to find secret-related keywords
- Looks for terms like: `hardcoded`, `secret`, `password`, `api key`, `token`, `credential`
- Provides a summary of issues found with severity levels

### OPA Detection (`snyk-secrets-opa-check.sh`)
- Runs Snyk Code analysis and converts results to SARIF format
- Evaluates findings against OPA policy rules (`policies/secrets_only_policy.rego`)
- Provides detailed categorization of secret types
- Falls back to simple text matching if OPA evaluation fails

## 🧪 Testing

### Test the hooks manually:
```bash
# Test simple detection
./scripts/snyk-secrets-simple.sh

# Test OPA detection
./scripts/snyk-secrets-opa-check.sh

# Run all pre-commit hooks
pre-commit run --all-files
```

### Create test files with secrets:
```bash
# Create a test file with hardcoded secrets
echo 'const API_KEY = "sk-1234567890abcdef";' > test-secrets.js
echo 'const password = "admin123";' >> test-secrets.js

# Try to commit (should be blocked)
git add test-secrets.js
git commit -m "test secrets detection"
```

## 🚨 What Gets Detected

The system will block commits containing:

- **Hardcoded passwords**: `password = "secret123"`
- **API keys**: `api_key = "sk-1234567890abcdef"`
- **Authentication tokens**: `token = "ghp_1234567890abcdef"`
- **Database credentials**: `db_password = "admin123"`
- **OAuth secrets**: `client_secret = "oauth_secret_123"`
- **Cloud provider keys**: AWS access keys, Azure secrets, etc.
- **Service credentials**: Stripe keys, SendGrid tokens, etc.

## 🔧 Customization

### Modify Detection Rules

Edit `policies/secrets_only_policy.rego` to customize what gets detected:

```rego
# Add new secret keywords
secret_keywords := {
    "hardcoded",
    "secret",
    "password",
    "your_custom_keyword"
}

# Add new secret types
classify_secret_type(message) := secret_type if {
    contains(lower(message), "custom_secret_type")
    secret_type := "custom_type"
}
```

### Skip Hooks When Needed

```bash
# Skip all hooks for emergency commits
git commit --no-verify -m "emergency fix"

# Skip specific hooks
SKIP=snyk-secrets-opa git commit -m "skip only OPA hook"

# Skip both secret detection hooks
SKIP=snyk-secrets-opa,snyk-secrets-simple git commit -m "skip both hooks"
```

## 📋 Output Examples

### Successful Scan
```
🚀 Simple secrets detection...
💻 Scanning code files...
✅ No secrets found
```

### Blocked Commit
```
❌ Hardcoded secrets detected!

📊 Summary: 3 security issue(s) found
  • High severity: 2
  • Medium severity: 1

🔍 Secret-Related Issues:
  ✗ [HIGH] Hardcoded Secret
  Path: auth-service.js, line 11
  Info: Avoid hardcoding values that are meant to be secret...

❌ Commit blocked due to hardcoded secrets!
💡 Use environment variables instead of hardcoded values
```

## 🛠️ Troubleshooting

### Common Issues

1. **"Snyk not found"**
   ```bash
   npm install -g snyk
   snyk auth
   ```

2. **"jq not found"**
   ```bash
   brew install jq  # macOS
   apt install jq   # Linux
   ```

3. **"OPA not found"**
   ```bash
   # Download and install OPA
   curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
   chmod +x opa
   sudo mv opa /usr/local/bin/
   ```

4. **"Policy file not found"**
   ```bash
   # Make sure you're in the project root directory
   ls policies/secrets_only_policy.rego
   ```

5. **Scripts not executable**
   ```bash
   chmod +x scripts/snyk-secrets-simple.sh
   chmod +x scripts/snyk-secrets-opa-check.sh
   ```

### Debug Mode

Run scripts manually to see detailed output:
```bash
./scripts/snyk-secrets-simple.sh
./scripts/snyk-secrets-opa-check.sh
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🔗 Related Links

- [Snyk Code Documentation](https://docs.snyk.io/snyk-code)
- [Open Policy Agent](https://www.openpolicyagent.org/)
- [Pre-commit Framework](https://pre-commit.com/)

---

**Made with ❤️ for secure coding practices**
