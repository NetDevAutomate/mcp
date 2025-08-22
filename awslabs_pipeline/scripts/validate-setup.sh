#!/bin/bash
# Setup Validation Script for AWS Labs CI Pipeline
# Validates that the pipeline is properly configured and secure

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Validation results
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
WARNINGS=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    ((WARNINGS++))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ((CRITICAL_ISSUES++))
}

log_high_issue() {
    echo -e "${RED}[HIGH]${NC} $1"
    ((HIGH_ISSUES++))
}

log_medium_issue() {
    echo -e "${YELLOW}[MEDIUM]${NC} $1"
    ((MEDIUM_ISSUES++))
}

# Change to project root
cd "$PROJECT_ROOT"

log_info "🔍 Starting AWS Labs CI Pipeline Validation"
log_info "Project Root: $PROJECT_ROOT"
echo "=================================="

# 1. CRITICAL SECURITY VALIDATION
log_info "🔒 Security Validation"

# Check for hardcoded credentials in code files
if grep -r "sk-\|ghp_\|pypi-\|aws_secret" --include="*.py" --include="*.sh" --include="*.yml" --include="*.yaml" . 2>/dev/null | grep -v ".secrets.template"; then
    log_error "SECURITY: Hardcoded credentials found in code files"
else
    log_success "No hardcoded credentials found in code"
fi

# Check secrets file security
if [[ -f "config/.secrets" ]]; then
    if [[ "$(stat -f %A config/.secrets 2>/dev/null || stat -c %a config/.secrets 2>/dev/null)" == "600" ]]; then
        log_success "config/.secrets has proper permissions (600)"
    else
        log_high_issue "config/.secrets should have 600 permissions: chmod 600 config/.secrets"
    fi
else
    log_warning "config/.secrets not found - copy from config/.secrets.template"
fi

# Check .gitignore for secrets
if [[ -f ".gitignore" ]] && grep -q "config/\.secrets" .gitignore; then
    log_success ".gitignore properly excludes secrets file"
else
    log_high_issue ".secrets file not in .gitignore - risk of credential exposure"
fi

# 2. DEPENDENCY VALIDATION
log_info "📦 Dependency Validation"

# Check for pyproject.toml
if [[ -f "pyproject.toml" ]]; then
    log_success "pyproject.toml found"

    # Check for required dependencies
    if grep -q "rich\|pydantic" pyproject.toml; then
        log_success "Core dependencies declared"
    else
        log_medium_issue "Missing core dependencies in pyproject.toml"
    fi
else
    log_error "CRITICAL: pyproject.toml not found"
fi

# Check for requirements.uv
if [[ -f "requirements.uv" ]] && [[ -s "requirements.uv" ]]; then
    log_success "requirements.uv populated with dependencies"

    # Check for security hashes
    if grep -q "\-\-hash=" requirements.uv; then
        log_success "Dependencies include security hashes"
    else
        log_medium_issue "Dependencies missing security hashes"
    fi
else
    log_medium_issue "requirements.uv is empty or missing"
fi

# Check Python version compatibility
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if [[ "$PYTHON_VERSION" == "3.10" ]] || [[ "$PYTHON_VERSION" == "3.11" ]] || [[ "$PYTHON_VERSION" == "3.12" ]]; then
        log_success "Python version ($PYTHON_VERSION) is compatible"
    else
        log_medium_issue "Python version ($PYTHON_VERSION) may not be optimal (recommend 3.10-3.12)"
    fi
else
    log_error "Python3 not found"
fi

# 3. TOOL AVAILABILITY
log_info "🔧 Tool Availability"

# Check required tools
REQUIRED_TOOLS=("docker" "uv" "git")
OPTIONAL_TOOLS=("act" "orb" "pre-commit")

for tool in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        log_success "$tool is available"
    else
        log_error "REQUIRED TOOL MISSING: $tool"
    fi
done

for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        log_success "$tool is available"
    else
        log_warning "$tool not found (optional but recommended)"
    fi
done

# Check Docker daemon
if command -v docker &> /dev/null; then
    if docker info &> /dev/null; then
        log_success "Docker daemon is running"
    else
        log_high_issue "Docker daemon is not running or not accessible"
    fi
fi

# Check OrbStack specifically for macOS
if [[ "$(uname)" == "Darwin" ]]; then
    if command -v orb &> /dev/null || [[ -f "/Applications/OrbStack.app/Contents/MacOS/orb" ]]; then
        log_success "OrbStack detected (optimal for macOS)"
    else
        log_warning "OrbStack not found - consider installing for better performance"
    fi
fi

# 4. CONFIGURATION VALIDATION
log_info "⚙️ Configuration Validation"

# Check essential config files
CONFIG_FILES=("config/.env" "config/.secrets.template")
for file in "${CONFIG_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        log_success "$file exists"
    else
        log_medium_issue "$file missing"
    fi
done

# Check workflow files
if [[ -d ".github/workflows" ]]; then
    WORKFLOW_COUNT=$(find .github/workflows -name "*.yml" -o -name "*.yaml" | wc -l)
    if [[ $WORKFLOW_COUNT -gt 0 ]]; then
        log_success "$WORKFLOW_COUNT GitHub Actions workflows found"
    else
        log_medium_issue "No workflow files found in .github/workflows/"
    fi
else
    log_medium_issue ".github/workflows directory not found"
fi

# Check .actrc configuration
if [[ -f ".actrc" ]] || [[ -f "config/act/.actrc" ]]; then
    log_success "Act configuration found"
else
    log_warning "No .actrc configuration found - will use defaults"
fi

# 5. PROJECT STRUCTURE VALIDATION
log_info "🏗️ Project Structure Validation"

# Check essential directories
ESSENTIAL_DIRS=("scripts" "config" "src" "tests")
for dir in "${ESSENTIAL_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        log_success "$dir/ directory exists"
    else
        log_medium_issue "$dir/ directory missing"
    fi
done

# Check Python package structure
if [[ -f "src/awslabs_ci_tool/__init__.py" ]]; then
    log_success "Python package structure correct"
else
    log_medium_issue "Python package structure incomplete"
fi

# Check test structure
if [[ -d "tests" ]]; then
    TEST_FILES=$(find tests -name "test_*.py" | wc -l)
    if [[ $TEST_FILES -gt 0 ]]; then
        log_success "$TEST_FILES test files found"
    else
        log_warning "No test files found in tests/"
    fi
else
    log_warning "No tests directory found"
fi

# 6. INSTALLATION VALIDATION
log_info "📋 Installation Validation"

# Try to import the package
if python3 -c "import awslabs_ci_tool; print('Import successful')" 2>/dev/null; then
    log_success "Package can be imported"
else
    log_medium_issue "Package cannot be imported - run 'uv sync --dev'"
fi

# Try to import ci_tool
if python3 -c "import ci_tool; print('Core module OK')" 2>/dev/null; then
    log_success "Core module can be imported"
else
    log_medium_issue "Core module cannot be imported - check PYTHONPATH"
fi

# Test CLI entry point
if [[ -f "src/awslabs_ci_tool/cli.py" ]]; then
    if python3 src/awslabs_ci_tool/cli.py --help &>/dev/null; then
        log_success "CLI entry point functional"
    else
        log_medium_issue "CLI entry point has issues"
    fi
fi

# 7. ENVIRONMENT VALIDATION
log_info "🌍 Environment Validation"

# Check environment variables that should be set
RECOMMENDED_VARS=("AWS_REGION" "PYTHON_VERSION")
for var in "${RECOMMENDED_VARS[@]}"; do
    if [[ -n "${!var:-}" ]]; then
        log_success "$var is set: ${!var}"
    else
        log_warning "$var not set (recommended)"
    fi
done

# Check for AWS credentials if needed
if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
    log_success "AWS credentials configured"
elif [[ -f "$HOME/.aws/credentials" ]] || [[ -f "$HOME/.aws/config" ]]; then
    log_success "AWS credentials configured via AWS CLI"
else
    log_warning "No AWS credentials found (may be needed for some features)"
fi

# 8. FINAL SUMMARY
echo "=================================="
log_info "📊 Validation Summary"

if [[ $CRITICAL_ISSUES -eq 0 ]] && [[ $HIGH_ISSUES -eq 0 ]]; then
    log_success "✅ Pipeline is ready for use!"

    echo ""
    echo "🚀 Quick Start Commands:"
    echo "  awslabs-ci full-ci                    # Run complete pipeline"
    echo "  awslabs-ci python-tests --target .    # Test current project"
    echo "  awslabs-ci setup-project /path/to/project  # Setup new project"
    echo ""

    EXIT_CODE=0
else
    log_error "❌ Pipeline has issues that need to be resolved"

    echo ""
    echo "🔧 Issues Summary:"
    echo "  Critical Issues: $CRITICAL_ISSUES (must fix)"
    echo "  High Issues: $HIGH_ISSUES (should fix)"
    echo "  Medium Issues: $MEDIUM_ISSUES (consider fixing)"
    echo "  Warnings: $WARNINGS (informational)"
    echo ""

    EXIT_CODE=1
fi

echo "For detailed troubleshooting, see: docs/troubleshooting.md"
echo "For security best practices, see: docs/security.md"
echo "=================================="

exit $EXIT_CODE
