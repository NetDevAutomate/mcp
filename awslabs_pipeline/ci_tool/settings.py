"""Settings management for AWS Labs CI Pipeline.

Handles configuration resolution from multiple sources with proper precedence:
1. Explicit parameters (highest priority)
2. Environment variables (CI_TOOL_* or AWSLABS_*)
3. pyproject.toml [tool.ci_tool] section
4. Default values (lowest priority)
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # Python < 3.11 fallback
    except ImportError:
        tomllib = None


@dataclass
class Settings:
    """Configuration settings for the CI pipeline."""

    project_root: Path
    dist_dir: Path
    coverage_dir: Path
    reports_dir: Path
    cache_dir: Path
    verbose: bool

    @classmethod
    def load(
        cls,
        *,
        project_root: Path | None = None,
        dist_dir: Path | None = None,
        coverage_dir: Path | None = None,
        reports_dir: Path | None = None,
        cache_dir: Path | None = None,
        verbose: bool | None = None,
    ) -> "Settings":
        """Load settings with precedence: explicit > env > pyproject.toml > defaults."""

        # Resolve project root
        root = project_root or Path.cwd()

        # Load pyproject.toml configuration
        pyproject_config = cls._load_pyproject_config(root)

        # Resolve each setting with precedence
        resolved_dist = (
            dist_dir
            or cls._get_path_from_env("CI_TOOL_DIST_DIR", "AWSLABS_ARTIFACTS_DIR")
            or cls._get_from_pyproject(pyproject_config, "paths.dist")
            or root / "dist"
        )

        resolved_coverage = (
            coverage_dir
            or cls._get_path_from_env("CI_TOOL_COVERAGE_DIR")
            or cls._get_from_pyproject(pyproject_config, "paths.coverage")
            or root / "coverage"
        )

        resolved_reports = (
            reports_dir
            or cls._get_path_from_env("CI_TOOL_REPORTS_DIR", "AWSLABS_REPORTS_DIR")
            or cls._get_from_pyproject(pyproject_config, "paths.reports")
            or root / "reports"
        )

        resolved_cache = (
            cache_dir
            or cls._get_path_from_env("CI_TOOL_CACHE_DIR", "AWSLABS_CACHE_DIR")
            or cls._get_from_pyproject(pyproject_config, "paths.cache")
            or root / "cache"
        )

        resolved_verbose = (
            verbose
            if verbose is not None
            else cls._get_bool_from_env("CI_TOOL_VERBOSE")
            or cls._get_from_pyproject(pyproject_config, "verbose")
            or False
        )

        settings = cls(
            project_root=root,
            dist_dir=resolved_dist,
            coverage_dir=resolved_coverage,
            reports_dir=resolved_reports,
            cache_dir=resolved_cache,
            verbose=resolved_verbose,
        )

        # Validate settings
        settings.validate()

        return settings

    def validate(self) -> None:
        """Validate settings and paths."""
        if not self.project_root.exists():
            raise ValueError(f"Project root does not exist: {self.project_root}")

        # Check write permissions for output directories
        for dir_name, path in [
            ("dist", self.dist_dir),
            ("coverage", self.coverage_dir),
            ("reports", self.reports_dir),
            ("cache", self.cache_dir),
        ]:
            parent = path.parent
            if parent.exists() and not os.access(parent, os.W_OK):
                raise PermissionError(f"No write permission for {dir_name} directory: {parent}")

    def ensure_dirs(self, logger) -> None:
        """Create all necessary directories."""
        dirs = [
            ("Dist", self.dist_dir),
            ("Coverage", self.coverage_dir),
            ("Reports", self.reports_dir),
            ("Cache", self.cache_dir),
        ]

        for name, path in dirs:
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                logger.info(f"{name}: {path}")

    @staticmethod
    def _load_pyproject_config(project_root: Path) -> dict[str, Any]:
        """Load configuration from pyproject.toml."""
        pyproject_path = project_root / "pyproject.toml"

        if not pyproject_path.exists() or tomllib is None:
            return {}

        try:
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
                return data.get("tool", {}).get("ci_tool", {})
        except Exception:
            # Return empty dict on any parsing error
            return {}

    @staticmethod
    def _get_path_from_env(*env_vars: str) -> Path | None:
        """Get path from environment variables (try each in order)."""
        for var in env_vars:
            value = os.getenv(var)
            if value:
                return Path(value)
        return None

    @staticmethod
    def _get_bool_from_env(env_var: str) -> bool | None:
        """Get boolean from environment variable."""
        value = os.getenv(env_var, "").lower()
        if value in ("true", "1", "yes", "on"):
            return True
        elif value in ("false", "0", "no", "off"):
            return False
        return None

    @staticmethod
    def _get_from_pyproject(config: dict[str, Any], key: str) -> Any | None:
        """Get value from pyproject.toml config using dot notation."""
        if not config:
            return None

        try:
            current = config
            for part in key.split("."):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            return Path(current) if isinstance(current, str) else current
        except (KeyError, TypeError, AttributeError):
            return None
