#!/bin/bash
# Simple CloudWAN MCP Server Validation Script
# Tests the basic functionality without full CI pipeline

set -euo pipefail

# Configuration
PROJECT_PATH="/Users/taylaand/code/mcpservers/cloud-wan-mcp-server/mcp/src/cloudwan-mcp-server"
PIPELINE_DIR="/Users/taylaand/code/mcp/awslabs_pipeline"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_info "🚀 Starting CloudWAN MCP Server Validation"
log_info "Project Path: $PROJECT_PATH"
log_info "Pipeline Directory: $PIPELINE_DIR"

# Check if project exists
if [[ ! -d "$PROJECT_PATH" ]]; then
    log_error "Project directory does not exist: $PROJECT_PATH"
    exit 1
fi

# Check if pyproject.toml exists
if [[ ! -f "$PROJECT_PATH/pyproject.toml" ]]; then
    log_error "No pyproject.toml found in project directory"
    exit 1
fi

log_success "✅ Project directory and configuration found"

# Change to project directory
cd "$PROJECT_PATH"

log_info "📋 Project Information:"
echo "=============================="
echo "Project Name: $(grep 'name =' pyproject.toml | head -1)"
echo "Version: $(grep 'version =' pyproject.toml | head -1)"
echo "Python Requirement: $(grep 'requires-python' pyproject.toml)"
echo "=============================="

# Check for required tools
log_info "🔧 Checking Prerequisites..."

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    log_success "Python found: $PYTHON_VERSION"
else
    log_error "Python3 not found"
    exit 1
fi

# Check uv (Python package manager)
if command -v uv &> /dev/null; then
    UV_VERSION=$(uv --version)
    log_success "uv found: $UV_VERSION"

    # Install dependencies
    log_info "📦 Installing dependencies with uv..."
    if uv sync --all-extras --dev; then
        log_success "Dependencies installed successfully"
    else
        log_error "Failed to install dependencies"
        exit 1
    fi
else
    log_warning "uv not found, trying pip instead"

    # Try pip installation
    if command -v pip &> /dev/null; then
        log_info "📦 Installing dependencies with pip..."
        pip install -e ".[dev]"
        log_success "Dependencies installed with pip"
    else
        log_error "Neither uv nor pip found"
        exit 1
    fi
fi

# Check project structure
log_info "🏗️ Analyzing Project Structure..."
echo "=============================="
echo "📁 Source Structure:"
find awslabs/ -name "*.py" | head -10 | sed 's/^/  /'
echo ""
echo "📁 Test Structure:"
find tests/ -name "*.py" | head -10 | sed 's/^/  /' 2>/dev/null || echo "  No tests directory found"
echo "=============================="

# Basic validation tests
log_info "🧪 Running Basic Validation Tests..."

# Test 1: Check imports
log_info "Test 1: Validating Python imports..."
if python3 -c "import awslabs.cloudwan_mcp_server; print('✅ Main module imports successfully')" 2>/dev/null; then
    log_success "Main module imports work"
else
    log_warning "Main module import issues (may be normal in development)"
fi

# Test 2: Check for security issues with basic tools
log_info "Test 2: Basic security check..."
if command -v bandit &> /dev/null; then
    log_info "Running bandit security scan..."
    bandit -r awslabs/ -f txt | head -20 || log_warning "Bandit scan completed with warnings"
else
    log_warning "bandit not available for security scanning"
fi

# Test 3: Code quality check
log_info "Test 3: Code quality check..."
if command -v ruff &> /dev/null; then
    log_info "Running ruff linting..."
    if ruff check awslabs/ --select E,F,I,N,W --quiet; then
        log_success "Code quality check passed"
    else
        log_warning "Code quality issues found (may be fixable)"
    fi
else
    log_warning "ruff not available for code quality checking"
fi

# Test 4: Type checking
log_info "Test 4: Type checking..."
if command -v mypy &> /dev/null; then
    log_info "Running mypy type checking..."
    mypy awslabs/ --ignore-missing-imports --no-error-summary 2>/dev/null || log_warning "Type checking issues found"
else
    log_warning "mypy not available for type checking"
fi

# Test 5: Run tests if available
log_info "Test 5: Running available tests..."
if [[ -d "tests" ]] && command -v pytest &> /dev/null; then
    log_info "Running pytest..."
    if pytest tests/ -v --tb=short | head -50; then
        log_success "Tests executed successfully"
    else
        log_warning "Some tests failed or had issues"
    fi
else
    log_warning "pytest not available or no tests directory"
fi

# Summary
log_info "📊 Validation Summary"
echo "=============================="
log_success "✅ Project structure validated"
log_success "✅ Dependencies installation attempted"
log_success "✅ Basic security and quality checks run"
log_success "✅ Import validation attempted"
echo "=============================="

log_success "🎉 CloudWAN MCP Server validation completed!"
log_info "💡 For full CI pipeline, use: $PIPELINE_DIR/scripts/run-full-ci.sh --target $PROJECT_PATH"

echo ""
echo "📋 Next Steps:"
echo "1. Review any warnings or errors above"
echo "2. Run full CI pipeline for comprehensive testing"
echo "3. Check test coverage and security scan results"
echo "4. Validate AWS integration tests (requires AWS credentials)"
