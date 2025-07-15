# policies/secrets_only_policy.rego
# OPA policy that only blocks commits containing hardcoded secrets

package snyk.security.secrets

import rego.v1

# Default decision - allow commits unless secrets are found
default allow := true

# Block commit if any hardcoded secrets are detected
allow := false if {
    count(secret_violations) > 0
}

# Identify secret violations from Snyk Code results
secret_violations contains violation if {
    some result in input.runs[0].results
    violation := create_violation(result)
    is_secret_violation(violation)
}

# Create standardized violation object
create_violation(result) := violation if {
    violation := {
        "rule_id": result.ruleId,
        "message": result.message.text,
        "severity": result.level,
        "file": result.locations[0].physicalLocation.artifactLocation.uri,
        "line": result.locations[0].physicalLocation.region.startLine,
        "cwe": extract_cwe(result.ruleId),
        "secret_type": classify_secret_type(result.message.text, result.ruleId)
    }
}

# Extract CWE from rule ID
extract_cwe(rule_id) := cwe if {
    regex.match(`CWE-\d+`, rule_id)
    cwe := regex.find_n(`CWE-\d+`, rule_id, 1)[0]
} else := ""

# Classify the type of secret detected
classify_secret_type(message, rule_id) := secret_type if {
    contains(lower(message), "api key")
    secret_type := "api_key"
} else := secret_type if {
    contains(lower(message), "password")
    secret_type := "password"
} else := secret_type if {
    contains(lower(message), "token")
    secret_type := "token"
} else := secret_type if {
    contains(lower(message), "private key")
    secret_type := "private_key"
} else := secret_type if {
    contains(lower(message), "secret")
    secret_type := "generic_secret"
} else := secret_type if {
    contains(lower(message), "credential")
    secret_type := "credential"
} else := secret_type if {
    contains(lower(message), "connection string")
    secret_type := "connection_string"
} else := secret_type if {
    contains(lower(message), "certificate")
    secret_type := "certificate"
} else := "unknown"

# Define what constitutes a secret violation
is_secret_violation(violation) if {
    # Block based on secret-related CWEs
    violation.cwe in secret_cwes
}

is_secret_violation(violation) if {
    # Block based on message content (case-insensitive)
    some keyword in secret_keywords
    contains(lower(violation.message), keyword)
}

is_secret_violation(violation) if {
    # Block based on rule ID patterns
    some pattern in secret_rule_patterns
    regex.match(pattern, violation.rule_id)
}

# Define secret-related CWEs
secret_cwes := {
    "CWE-798",  # Use of Hard-coded Credentials
    "CWE-259",  # Use of Hard-coded Password
    "CWE-321",  # Use of Hard-coded Cryptographic Key
    "CWE-522",  # Insufficiently Protected Credentials
    "CWE-256",  # Unprotected Storage of Credentials
    "CWE-257",  # Storing Passwords in a Recoverable Format
    "CWE-260",  # Password in Configuration File
    "CWE-261",  # Weak Cryptography for Passwords
    "CWE-262",  # Not Using Password Aging
    "CWE-263",  # Password Aging with Long Expiration
    "CWE-309",  # Use of Password System for Primary Authentication
    "CWE-312",  # Cleartext Storage of Sensitive Information
    "CWE-313",  # Cleartext Storage in a File or on Disk
    "CWE-314",  # Cleartext Storage in the Registry
    "CWE-315",  # Cleartext Storage of Sensitive Information in a Cookie
    "CWE-316",  # Cleartext Storage of Sensitive Information in Memory
    "CWE-317",  # Cleartext Storage of Sensitive Information in GUI
    "CWE-318",  # Cleartext Storage of Sensitive Information in Executable
    "CWE-319",  # Cleartext Transmission of Sensitive Information
    "CWE-523",  # Unprotected Transport of Credentials
    "CWE-549",  # Missing Password Field Masking
    "CWE-550",  # Server-generated Error Message Exposes Sensitive Information
    "CWE-614"   # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
}

# Define secret-related keywords to look for in messages
secret_keywords := {
    "hardcoded",
    "hard-coded",
    "hard coded",
    "password",
    "secret",
    "api key",
    "private key",
    "access key",
    "token",
    "credential",
    "connection string",
    "database password",
    "auth token",
    "bearer token",
    "jwt secret",
    "encryption key",
    "certificate",
    "passphrase",
    "ssh key",
    "oauth",
    "client secret",
    "client id",
    "aws secret",
    "azure key",
    "gcp key",
    "github token",
    "slack token",
    "stripe key",
    "twilio auth",
    "sendgrid key",
    "mongodb uri",
    "redis password",
    "database url"
}

# Define patterns for rule IDs that indicate secrets
secret_rule_patterns := {
    ".*[Hh]ardcoded.*",
    ".*[Ss]ecret.*",
    ".*[Pp]assword.*",
    ".*[Cc]redential.*",
    ".*[Tt]oken.*",
    ".*[Kk]ey.*",
    ".*[Aa]uth.*"
}

# Generate detailed violation report for secrets only
violation_report := {
    "blocked": count(secret_violations) > 0,
    "total_secret_violations": count(secret_violations),
    "secret_violations": secret_violations,
    "secrets_by_type": secrets_by_type,
    "secrets_by_severity": secrets_by_severity,
    "affected_files": affected_files
}

# Group secrets by type
secrets_by_type := {type: count([v | v := secret_violations[_]; v.secret_type == type]) |
    some type in {v.secret_type | v := secret_violations[_]}
}

# Group secrets by severity
secrets_by_severity := {severity: count([v | v := secret_violations[_]; v.severity == severity]) |
    some severity in {v.severity | v := secret_violations[_]}
}

# List affected files
affected_files := {file | some v in secret_violations; file := v.file}

# Optional: Allow certain files to have secrets (e.g., test files, examples)
# Uncomment and customize as needed
/*
allow := true if {
    count(secret_violations) > 0
    all_violations_in_allowed_files
}

all_violations_in_allowed_files if {
    every violation in secret_violations {
        is_allowed_file(violation.file)
    }
}

is_allowed_file(file) if {
    startswith(file, "test/")
}

is_allowed_file(file) if {
    startswith(file, "tests/")
}

is_allowed_file(file) if {
    startswith(file, "examples/")
}

is_allowed_file(file) if {
    contains(file, "mock")
}

is_allowed_file(file) if {
    contains(file, "fixture")
}
*/
