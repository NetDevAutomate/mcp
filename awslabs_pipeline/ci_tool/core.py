"""Core functionality for AWS Labs CI Pipeline.

This module provides the main execution logic for the CI pipeline,
including runner selection, workflow execution, and process management.
"""

import os
import platform
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path

from .settings import Settings

try:
    from rich.console import Console
    from rich.text import Text

    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


class CIError(Exception):
    """Base exception for CI pipeline errors."""


class RunnerError(CIError):
    """Runner-specific errors."""


class ConfigError(CIError):
    """Configuration errors."""


class ValidationError(CIError):
    """Input validation errors."""


class Logger:
    """Enhanced logger with color support and Rich integration."""

    def __init__(self, use_color: bool = True):
        self.use_color = use_color
        self.console = Console() if _HAS_RICH and use_color else None

        # ANSI color codes for terminals without Rich
        self.colors = (
            {
                "info": "\033[0;34m",  # Blue
                "success": "\033[0;32m",  # Green
                "warning": "\033[1;33m",  # Yellow
                "error": "\033[0;31m",  # Red
                "reset": "\033[0m",  # Reset
            }
            if use_color
            else dict.fromkeys(["info", "success", "warning", "error", "reset"], "")
        )

    def _print(self, level: str, message: str) -> None:
        """Print message with appropriate formatting."""
        if self.console:
            color_map = {"info": "blue", "success": "green", "warning": "yellow", "error": "red"}
            self.console.print(f"[{level.upper()}]", style=color_map[level], end=" ")
            self.console.print(message)
        else:
            color = self.colors[level]
            reset = self.colors["reset"]
            print(f"{color}[{level.upper()}]{reset} {message}")

    def info(self, message: str) -> None:
        """Log info message."""
        self._print("info", message)

    def success(self, message: str) -> None:
        """Log success message."""
        self._print("success", message)

    def warning(self, message: str) -> None:
        """Log warning message."""
        self._print("warning", message)

    def error(self, message: str) -> None:
        """Log error message."""
        self._print("error", message)


class Runner(ABC):
    """Abstract base class for CI runners."""

    @abstractmethod
    def name(self) -> str:
        """Get runner name."""

    @abstractmethod
    def available(self) -> bool:
        """Check if runner is available on this system."""

    @abstractmethod
    def run_workflows(
        self, workflows: list[tuple[str, str]], *, settings: Settings, env: dict[str, str], **kwargs
    ) -> list[tuple[str, int]]:
        """Run workflows and return results."""


class NativeRunner(Runner):
    """Native runner that executes commands directly on the host."""

    def name(self) -> str:
        return "native"

    def available(self) -> bool:
        return True  # Always available

    def run_workflows(
        self, workflows: list[tuple[str, str]], *, settings: Settings, env: dict[str, str], **kwargs
    ) -> list[tuple[str, int]]:
        """Run workflows natively."""
        results = []
        for name, command in workflows:
            # Simple native execution for now
            result_code = _stream_process([command], env=env)
            results.append((name, result_code))
        return results


class _ActBase(Runner):
    """Base class for Act-based runners."""

    def available(self) -> bool:
        """Check if act and docker are available."""
        return shutil.which("act") is not None and shutil.which("docker") is not None and _docker_up()

    def _act_args(
        self, *, settings: Settings, env: dict[str, str], event_file: str | None = None, verbose: bool = False
    ) -> list[str]:
        """Build act command arguments."""
        args = [
            "act",
            "-P",
            "ubuntu-latest=catthehacker/ubuntu:act-latest",
            "--env-file",
            "config/.env",
            "--secret-file",
            "config/.secrets",
            "--artifact-server-path",
            str(settings.dist_dir),
        ]

        # Add environment variables
        for key, value in env.items():
            args.extend(["--env", f"{key}={value}"])

        # Add event file if provided
        if event_file:
            args.extend(["--eventpath", event_file])

        # Add verbose if requested
        if verbose:
            args.append("--verbose")

        return args


class ActRunner(_ActBase):
    """Standard GitHub Actions runner using act."""

    def name(self) -> str:
        return "act"

    def run_workflows(
        self, workflows: list[tuple[str, str]], *, settings: Settings, env: dict[str, str], **kwargs
    ) -> list[tuple[str, int]]:
        """Run workflows using act."""
        results = []

        for name, workflow_file in workflows:
            act_args = self._act_args(
                settings=settings, env=env, event_file=kwargs.get("event_file"), verbose=kwargs.get("verbose", False)
            )
            act_args.extend(["-W", workflow_file])

            result_code = _stream_process(act_args, env=env)
            results.append((name, result_code))

        return results


class OrbStackRunner(_ActBase):
    """Enhanced runner that uses OrbStack for better macOS performance."""

    def name(self) -> str:
        return "orbstack"

    def available(self) -> bool:
        """Check if OrbStack is available."""
        # Check via orb command
        if shutil.which("orb") is not None:
            return super().available()

        # Check via app path (macOS)
        app_path = Path("/Applications/OrbStack.app")
        return app_path.exists() and super().available()

    def _docker_socket(self) -> str | None:
        """Get OrbStack docker socket with platform detection."""
        candidates = [
            os.path.expanduser("~/.orbstack/run/docker.sock"),  # macOS
            "/var/run/docker.sock",  # Linux fallback
            os.environ.get("DOCKER_HOST", "").replace("unix://", ""),  # ENV override
        ]

        for sock_path in candidates:
            if sock_path and os.path.exists(sock_path) and os.access(sock_path, os.R_OK | os.W_OK):
                return f"unix://{sock_path}"

        return os.environ.get("DOCKER_HOST")  # Use environment if available

    def run_workflows(
        self, workflows: list[tuple[str, str]], *, settings: Settings, env: dict[str, str], **kwargs
    ) -> list[tuple[str, int]]:
        """Run workflows using act with OrbStack optimizations."""
        # Set OrbStack-specific environment
        orbstack_env = env.copy()
        socket = self._docker_socket()
        if socket:
            orbstack_env["DOCKER_HOST"] = socket

        results = []
        for name, workflow_file in workflows:
            act_args = self._act_args(
                settings=settings,
                env=orbstack_env,
                event_file=kwargs.get("event_file"),
                verbose=kwargs.get("verbose", False),
            )
            act_args.extend(["-W", workflow_file])

            result_code = _stream_process(act_args, env=orbstack_env)
            results.append((name, result_code))

        return results


class ARMRunner(_ActBase):
    """ARM64-optimized runner for Apple Silicon and ARM64 systems."""

    def name(self) -> str:
        return "arm64"

    def available(self) -> bool:
        """Check if we're on ARM64 and act/docker are available."""
        return platform.machine() in ("arm64", "aarch64") and super().available()

    def run_workflows(
        self, workflows: list[tuple[str, str]], *, settings: Settings, env: dict[str, str], **kwargs
    ) -> list[tuple[str, int]]:
        """Run workflows with ARM64 optimizations."""
        # Use ARM64 containers when available
        arm_env = env.copy()
        arm_env["DOCKER_PLATFORM"] = "linux/arm64/v8"

        results = []
        for name, workflow_file in workflows:
            act_args = self._act_args(
                settings=settings,
                env=arm_env,
                event_file=kwargs.get("event_file"),
                verbose=kwargs.get("verbose", False),
            )

            # Use ARM64 runner images
            act_args[act_args.index("catthehacker/ubuntu:act-latest")] = "catthehacker/ubuntu:act-latest-arm64"
            act_args.extend(["-W", workflow_file])

            result_code = _stream_process(act_args, env=arm_env)
            results.append((name, result_code))

        return results


def _docker_up() -> bool:
    """Check if Docker daemon is running with timeout."""
    try:
        result = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return False


def _stream_process(cmd: Sequence[str], env: dict[str, str] | None = None) -> int:
    """Execute command with proper validation and output streaming."""
    if not cmd or not cmd[0]:
        raise ValidationError("Command sequence cannot be empty")

    # Validate executable exists (for non-shell commands)
    if not shutil.which(cmd[0]):
        raise ValidationError(f"Executable not found: {cmd[0]}")

    # Sanitize environment variables
    safe_env = dict(os.environ)
    if env:
        # Only allow safe environment variables
        safe_keys = {
            "PATH",
            "HOME",
            "USER",
            "PROJECT_PATH",
            "COVERAGE_FILE",
            "GITHUB_REPOSITORY",
            "GITHUB_WORKSPACE",
            "RUNNER_OS",
            "DOCKER_HOST",
            "DOCKER_PLATFORM",
            "AWS_REGION",
        }
        for k, v in env.items():
            if k in safe_keys and isinstance(v, str):
                safe_env[k] = v

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=safe_env)

        # Stream output in real-time
        if proc.stdout:
            for line in proc.stdout:
                sys.stdout.write(line)

        return proc.wait()

    except Exception as e:
        raise RunnerError(f"Process execution failed: {e}") from e


def _select_runner(preferred: str | None = None) -> Runner:
    """Select best available runner with fallback chain."""
    preferred = preferred or os.getenv("AWSLABS_RUNNER")

    # Define runner priority with ARM64 first for performance
    candidates: list[Runner] = [
        ARMRunner(),  # Best performance on ARM64
        OrbStackRunner(),  # Best performance on macOS
        ActRunner(),  # Standard GitHub Actions
        NativeRunner(),  # Always available fallback
    ]

    # Filter to available runners
    available_runners = [(r, r.name()) for r in candidates if r.available()]

    # Try preferred first if specified
    if preferred:
        for runner, name in available_runners:
            if name == preferred.lower():
                return runner

    # Use first available
    if available_runners:
        return available_runners[0][0]

    raise RunnerError("No runners available. Install docker/act or check system requirements.")


def _delegate_if_exists(script_name: str, *args: str, settings: Settings, logger: Logger) -> int | None:
    """Delegate to shell script if it exists."""
    script_path = settings.project_root / "scripts" / script_name

    if not script_path.exists():
        return None

    if not os.access(script_path, os.X_OK):
        logger.warning(f"Script {script_name} exists but is not executable")
        return None

    logger.info(f"Delegating to {script_name}")
    cmd = [str(script_path)] + list(args)
    return _stream_process(cmd)


def run_full_ci(
    settings: Settings,
    logger: Logger,
    *,
    workflow: str = "all",
    clean: bool = False,
    event: str = "push",
    verbose: bool = False,
) -> int:
    """Run the complete CI pipeline."""
    logger.info(f"Starting full CI pipeline (workflow: {workflow})")

    # Try to delegate to shell script first
    script_result = _delegate_if_exists(
        "run-full-ci.sh",
        f"--workflow={workflow}",
        f"--event={event}",
        *(["--clean"] if clean else []),
        *(["--verbose"] if verbose else []),
        settings=settings,
        logger=logger,
    )

    if script_result is not None:
        return script_result

    # Native implementation fallback
    logger.info("Using native CI implementation")

    # Clean directories if requested
    if clean:
        logger.info("Cleaning previous artifacts...")
        for path in [settings.dist_dir, settings.cache_dir, settings.reports_dir]:
            if path.exists():
                shutil.rmtree(path)

    # Ensure output directories exist
    settings.ensure_dirs(logger)

    # Select appropriate runner
    try:
        runner = _select_runner()
        logger.info(f"Selected runner: {runner.name()}")
    except RunnerError as e:
        logger.error(f"Runner selection failed: {e}")
        return 1

    # Build environment
    env = {
        "PROJECT_PATH": str(settings.project_root),
        "GITHUB_REPOSITORY": "local/test-repo",
        "RUNNER_OS": platform.system(),
    }

    # Define workflow mappings
    workflow_map = {
        "all": [
            ("Python Tests", ".github/workflows/python.yml"),
            ("Pre-commit", ".github/workflows/pre-commit.yml"),
            ("Claude Review", ".github/workflows/claude-review.yml"),
            ("Build & Publish", ".github/workflows/publish.yml"),
        ],
        "python": [("Python Tests", ".github/workflows/python.yml")],
        "precommit": [("Pre-commit", ".github/workflows/pre-commit.yml")],
        "claude": [("Claude Review", ".github/workflows/claude-review.yml")],
        "publish": [("Build & Publish", ".github/workflows/publish.yml")],
    }

    workflows = workflow_map.get(workflow, workflow_map["all"])

    # Execute workflows
    try:
        results = runner.run_workflows(
            workflows, settings=settings, env=env, event_file=f"config/{event}-event.json", verbose=verbose
        )
    except Exception as e:
        logger.error(f"Workflow execution failed: {e}")
        return 1

    # Report results
    failures = [name for name, code in results if code != 0]
    if failures:
        logger.error(f"Failed workflows: {', '.join(failures)}")
        return 1
    else:
        logger.success("All workflows completed successfully")
        return 0


def run_python_tests(
    settings: Settings,
    logger: Logger,
    *,
    project_path: Path | None = None,
    python_version: str | None = None,
    coverage_only: bool = False,
    lint_only: bool = False,
    security_only: bool = False,
) -> int:
    """Run Python testing workflow."""
    target_path = project_path or settings.project_root

    # Check for Python project
    pyproject_path = target_path / "pyproject.toml"
    if not pyproject_path.exists():
        logger.error(f"No pyproject.toml found in {target_path}")
        return 1

    # Try to delegate to shell script first
    script_args = [str(target_path)]
    if python_version:
        script_args.extend(["--python-version", python_version])
    if coverage_only:
        script_args.append("--coverage")
    if lint_only:
        script_args.append("--lint")
    if security_only:
        script_args.append("--security")

    script_result = _delegate_if_exists("run-python-tests.sh", *script_args, settings=settings, logger=logger)

    if script_result is not None:
        return script_result

    # Native implementation
    logger.info("Using native Python testing")

    env = {"PROJECT_PATH": str(target_path), "PYTHON_VERSION": python_version or "3.11"}

    # Build pytest command based on options
    pytest_cmd = ["python", "-m", "pytest"]

    if coverage_only:
        pytest_cmd.extend(["--cov", "--cov-report=html", "--cov-report=xml"])
    elif lint_only:
        pytest_cmd = ["python", "-m", "ruff", "check", "."]
    elif security_only:
        pytest_cmd = ["python", "-m", "bandit", "-r", "."]
    else:
        pytest_cmd.extend(["-v", "--tb=short"])

    return _stream_process(pytest_cmd, env=env)


def setup_project(
    settings: Settings,
    logger: Logger,
    *,
    target_project: Path | None = None,
    force: bool = False,
    cloudwan_project: bool = False,
) -> int:
    """Set up a project for CI pipeline testing."""
    target = target_project or settings.project_root

    # Try to delegate to shell script first
    script_args = [str(target)]
    if force:
        script_args.append("--force")
    if cloudwan_project:
        script_args.append("--cloudwan-project")

    script_result = _delegate_if_exists("setup-project.sh", *script_args, settings=settings, logger=logger)

    if script_result is not None:
        return script_result

    # Native implementation
    logger.info(f"Setting up project: {target}")

    # Create basic files
    files_created = []

    # Create .pre-commit-config.yaml
    precommit_config = target / ".pre-commit-config.yaml"
    if not precommit_config.exists() or force:
        precommit_config.write_text("""# Pre-commit hooks for AWS Labs projects
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
""")
        files_created.append(".pre-commit-config.yaml")

    # Create .python-version
    python_version = target / ".python-version"
    if not python_version.exists() or force:
        python_version.write_text("3.11\n")
        files_created.append(".python-version")

    # Create tests directory
    tests_dir = target / "tests"
    if not tests_dir.exists():
        tests_dir.mkdir()
        (tests_dir / "__init__.py").write_text("")
        (tests_dir / "test_example.py").write_text('''"""Example tests."""

def test_example():
    """Example test that always passes."""
    assert True

def test_addition():
    """Test basic arithmetic."""
    assert 2 + 2 == 4
''')
        files_created.append("tests/")

    # Create CI config files
    settings.ensure_dirs(logger)

    config_dir = settings.project_root / "config"
    config_dir.mkdir(exist_ok=True)

    if not (config_dir / ".env").exists() or force:
        # Copy from our template
        files_created.append("config/.env")

    if not (config_dir / ".secrets").exists() or force:
        # Copy template
        files_created.append("config/.secrets")

    logger.success(f"Created files: {', '.join(files_created)}")
    return 0


def run_subcommand(command: str, **kwargs) -> int:
    """Run a specific CI subcommand."""
    # Load settings
    settings = Settings.load()
    logger = Logger()

    command_map = {
        "full-ci": lambda: run_full_ci(settings, logger, **kwargs),
        "python-tests": lambda: run_python_tests(settings, logger, **kwargs),
        "setup-project": lambda: setup_project(settings, logger, **kwargs),
    }

    if command in command_map:
        return command_map[command]()
    else:
        logger.error(f"Unknown command: {command}")
        return 1
