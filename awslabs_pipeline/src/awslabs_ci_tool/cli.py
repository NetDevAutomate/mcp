"""AWS Labs CI Tool - Command Line Interface.

Provides command-line access to the CI pipeline functionality with proper
error handling and security validation.
"""

import argparse
import sys
import warnings
from pathlib import Path

# Import core functionality with proper error handling
try:
    from ci_tool.core import Logger, run_full_ci, run_python_tests, setup_project
    from ci_tool.settings import Settings

    _CORE_AVAILABLE = True
except ImportError as e:
    warnings.warn(f"Core CI functionality not available: {e}")
    run_full_ci = None
    run_python_tests = None
    setup_project = None
    Settings = None
    Logger = None
    _CORE_AVAILABLE = False


def _check_core_available() -> bool:
    """Check if core functionality is available and provide helpful error."""
    if not _CORE_AVAILABLE:
        print("ERROR: ci_tool.core package not found.", file=sys.stderr)
        print("Run 'pip install -e .' or 'uv sync --dev' from project root.", file=sys.stderr)
        return False
    return True


def cmd_full_ci(args: argparse.Namespace) -> int:
    """Execute full CI pipeline."""
    if not _check_core_available():
        return 1

    try:
        settings = Settings.load(
            project_root=Path(args.project_root) if args.project_root else None, verbose=args.verbose
        )
        logger = Logger(use_color=not args.no_color)

        return run_full_ci(
            settings, logger, workflow=args.workflow, clean=args.clean, event=args.event, verbose=args.verbose
        )
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_python_tests(args: argparse.Namespace) -> int:
    """Execute Python testing workflow."""
    if not _check_core_available():
        return 1

    try:
        settings = Settings.load(
            project_root=Path(args.project_root) if args.project_root else None, verbose=args.verbose
        )
        logger = Logger(use_color=not args.no_color)

        return run_python_tests(
            settings,
            logger,
            project_path=Path(args.target) if args.target else None,
            python_version=args.python_version,
            coverage_only=args.coverage,
            lint_only=args.lint,
            security_only=args.security,
        )
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_setup_project(args: argparse.Namespace) -> int:
    """Set up project for CI testing."""
    if not _check_core_available():
        return 1

    try:
        settings = Settings.load(
            project_root=Path(args.project_root) if args.project_root else None, verbose=args.verbose
        )
        logger = Logger(use_color=not args.no_color)

        return setup_project(
            settings,
            logger,
            target_project=Path(args.target) if args.target else None,
            force=args.force,
            cloudwan_project=args.cloudwan_project,
        )
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_llm_proxy_start(args: argparse.Namespace) -> int:
    """Start LLM proxy for Bedrock integration."""
    try:
        import subprocess

        # Basic LLM proxy startup
        cmd = [
            "python",
            "-m",
            "litellm",
            "--config",
            "litellm_config.yaml",
            "--port",
            str(args.port),
            "--host",
            args.host,
        ]

        if args.verbose:
            print(f"Starting LLM proxy: {' '.join(cmd)}")

        result = subprocess.run(cmd)
        return result.returncode

    except Exception as e:
        print(f"ERROR: Failed to start LLM proxy: {e}", file=sys.stderr)
        return 1


def cmd_automated_review(args: argparse.Namespace) -> int:
    """Run automated code review using Claude Sonnet 4."""
    if not _check_core_available():
        return 1

    try:
        from ci_tool.code_reviewer import run_automated_review

        settings = Settings.load(
            project_root=Path(args.project_root) if args.project_root else None, verbose=args.verbose
        )
        logger = Logger(use_color=not args.no_color)

        target_path = Path(args.target) if args.target else settings.project_root

        # Run async code review
        import asyncio

        return asyncio.run(run_automated_review(settings, target_path, logger))

    except Exception as e:
        print(f"ERROR: Automated review failed: {e}", file=sys.stderr)
        return 1


def cmd_llm_proxy_stop(args: argparse.Namespace) -> int:
    """Stop LLM proxy."""
    try:
        import subprocess

        # Find and stop LLM proxy processes
        cmd = ["pkill", "-f", "litellm"]

        if args.verbose:
            print("Stopping LLM proxy processes...")

        result = subprocess.run(cmd, capture_output=True)

        if result.returncode == 0:
            print("LLM proxy stopped successfully")
        else:
            print("No LLM proxy processes found or failed to stop")

        return 0  # Don't fail if no processes found

    except Exception as e:
        print(f"ERROR: Failed to stop LLM proxy: {e}", file=sys.stderr)
        return 1


def create_parser() -> argparse.ArgumentParser:
    """Create the command line parser."""
    parser = argparse.ArgumentParser(prog="awslabs-ci", description="AWS Labs CI Pipeline - Local testing environment")

    # Global options
    parser.add_argument("--project-root", help="Project root directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Full CI command
    full_ci = subparsers.add_parser("full-ci", help="Run complete CI pipeline")
    full_ci.add_argument(
        "--workflow", default="all", choices=["all", "python", "precommit", "claude", "publish"], help="Workflow to run"
    )
    full_ci.add_argument("--clean", action="store_true", help="Clean artifacts before running")
    full_ci.add_argument(
        "--event",
        default="push",
        choices=["push", "pull_request", "release", "workflow_dispatch"],
        help="Event type to simulate",
    )
    full_ci.set_defaults(func=cmd_full_ci)

    # Python tests command
    python_tests = subparsers.add_parser("python-tests", help="Run Python testing workflow")
    python_tests.add_argument("--target", help="Target project directory")
    python_tests.add_argument("--python-version", help="Specific Python version to test")
    python_tests.add_argument("--coverage", action="store_true", help="Generate coverage reports only")
    python_tests.add_argument("--lint", action="store_true", help="Run linting only")
    python_tests.add_argument("--security", action="store_true", help="Run security scans only")
    python_tests.set_defaults(func=cmd_python_tests)

    # Setup project command
    setup = subparsers.add_parser("setup-project", help="Set up project for CI testing")
    setup.add_argument("target", nargs="?", help="Target project directory")
    setup.add_argument("--force", action="store_true", help="Force overwrite existing files")
    setup.add_argument("--cloudwan-project", action="store_true", help="Setup for CloudWAN MCP server project")
    setup.set_defaults(func=cmd_setup_project)

    # LLM proxy commands
    llm_start = subparsers.add_parser("llm-proxy-start", help="Start LLM proxy for Bedrock")
    llm_start.add_argument("--host", default="localhost", help="Proxy host")
    llm_start.add_argument("--port", type=int, default=4040, help="Proxy port")
    llm_start.set_defaults(func=cmd_llm_proxy_start)

    llm_stop = subparsers.add_parser("llm-proxy-stop", help="Stop LLM proxy")
    llm_stop.set_defaults(func=cmd_llm_proxy_stop)

    # Automated review command
    auto_review = subparsers.add_parser("automated-review", help="Run automated code review with Claude Sonnet 4")
    auto_review.add_argument("--target", help="Target project directory to review")
    auto_review.add_argument("--model", default="claude-sonnet-4", help="AI model to use for review")
    auto_review.set_defaults(func=cmd_automated_review)

    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
