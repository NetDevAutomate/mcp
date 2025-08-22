"""Automated code review engine using Claude Sonnet 4 via litellm proxy.

This module provides GitHub Copilot-style automated code review capabilities,
including best practices validation, documentation consolidation, file naming
validation, and directory structure cleanup.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .settings import Settings


@dataclass
class ReviewResult:
    """Results from automated code review."""

    overall_score: int  # 0-100
    critical_issues: list[str]
    warnings: list[str]
    suggestions: list[str]
    documentation_issues: list[str]
    file_naming_issues: list[str]
    structure_issues: list[str]
    summary: str


class CodeReviewer:
    """Automated code review engine using Claude Sonnet 4."""

    def __init__(
        self,
        endpoint: str = "http://localhost:4040/v1",
        api_key: str = "sk-litellm-bedrock-proxy-2025",
        model: str = "claude-sonnet-4",
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model
        self.client = httpx.AsyncClient(
            timeout=300.0,  # 5 minute timeout for code reviews
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # File naming patterns to detect and flag
        self.problematic_naming_patterns = [
            r".*_(original|new|updated|enhanced|fixed|temp|tmp)\.py$",
            r".*_(old|backup|copy|v\d+)\.py$",
            r".*_\d{8}\.py$",  # Date suffixes
            r".*\.(orig|bak|backup)$",
            r".*_copy\d*\.py$",
            r".*(Original|New|Updated|Enhanced|Fixed).*\.py$",
        ]

        # Essential files that should be in project root
        self.essential_root_files = {
            "README.md",
            "pyproject.toml",
            "LICENSE",
            "NOTICE",
            ".gitignore",
            "Dockerfile",
            "docker-healthcheck.sh",
            "CHANGELOG.md",
            "CONTRIBUTING.md",
            "MANIFEST.in",
        }

    async def review_project(self, project_path: Path, settings: Settings) -> ReviewResult:
        """Perform comprehensive automated code review."""

        # 1. Analyze project structure
        structure_analysis = await self._analyze_project_structure(project_path)

        # 2. Check file naming conventions
        naming_issues = self._check_file_naming(project_path)

        # 3. Validate directory structure
        structure_issues = self._validate_directory_structure(project_path)

        # 4. Perform AI-powered code review
        code_review = await self._perform_ai_code_review(project_path, structure_analysis)

        # 5. Check documentation consistency
        doc_issues = await self._validate_documentation(project_path)

        # 6. Calculate overall score
        score = self._calculate_score(code_review, naming_issues, structure_issues, doc_issues)

        return ReviewResult(
            overall_score=score,
            critical_issues=code_review.get("critical", []),
            warnings=code_review.get("warnings", []),
            suggestions=code_review.get("suggestions", []),
            documentation_issues=doc_issues,
            file_naming_issues=naming_issues,
            structure_issues=structure_issues,
            summary=code_review.get("summary", "Code review completed"),
        )

    async def _analyze_project_structure(self, project_path: Path) -> dict[str, Any]:
        """Analyze project structure and gather metadata."""

        analysis = {
            "project_type": "unknown",
            "primary_language": "python",
            "file_count": 0,
            "test_coverage": 0,
            "has_documentation": False,
            "has_tests": False,
            "dependencies": [],
        }

        # Detect project type
        if (project_path / "pyproject.toml").exists():
            analysis["project_type"] = "python_package"

            # Parse pyproject.toml for dependencies
            try:
                with open(project_path / "pyproject.toml") as f:
                    content = f.read()
                    # Extract dependencies (simple regex-based parsing)
                    deps = re.findall(r'"([^"]+)>=', content)
                    analysis["dependencies"] = deps[:10]  # Limit for review
            except Exception:
                pass

        # Count files
        py_files = list(project_path.rglob("*.py"))
        analysis["file_count"] = len(py_files)

        # Check for tests
        test_dirs = ["tests", "test", "testing"]
        analysis["has_tests"] = any((project_path / d).exists() for d in test_dirs)

        # Check for documentation
        doc_files = ["README.md", "docs/", "documentation/"]
        analysis["has_documentation"] = any((project_path / f).exists() for f in doc_files)

        return analysis

    def _check_file_naming(self, project_path: Path) -> list[str]:
        """Check for problematic file naming patterns."""
        issues = []

        # Find all Python files
        for py_file in project_path.rglob("*.py"):
            relative_path = py_file.relative_to(project_path)

            for pattern in self.problematic_naming_patterns:
                if re.match(pattern, str(relative_path), re.IGNORECASE):
                    issues.append(
                        f"NAMING: {relative_path} uses version-control naming pattern. "
                        f"Use git branches instead of file suffixes for version control."
                    )
                    break

        return issues

    def _validate_directory_structure(self, project_path: Path) -> list[str]:
        """Validate directory structure follows best practices."""
        issues = []

        # Check root directory cleanliness
        root_items = list(project_path.iterdir())
        non_essential_in_root = []

        for item in root_items:
            if item.is_file() and item.name not in self.essential_root_files:
                # Allow some common patterns
                if not any(
                    pattern in item.name.lower()
                    for pattern in [
                        ".env",
                        ".secrets",
                        ".python-version",
                        ".pre-commit",
                        "requirements",
                        "uv.lock",
                        ".gitignore",
                    ]
                ):
                    non_essential_in_root.append(item.name)

        if non_essential_in_root:
            issues.append(
                f"STRUCTURE: Non-essential files in project root: {', '.join(non_essential_in_root)}. "
                f"Consider moving to appropriate subdirectories."
            )

        # Check for standard Python project structure
        expected_dirs = {"src", "tests", "docs"}
        missing_standard_dirs = expected_dirs - {d.name for d in root_items if d.is_dir()}

        if missing_standard_dirs and (project_path / "pyproject.toml").exists():
            issues.append(f"STRUCTURE: Consider adding standard directories: {', '.join(missing_standard_dirs)}")

        # Check for nested package issues
        for py_file in project_path.rglob("*.py"):
            relative_path = py_file.relative_to(project_path)
            parts = relative_path.parts

            # Flag deeply nested structures (>5 levels)
            if len(parts) > 5:
                issues.append(
                    f"STRUCTURE: Deep nesting detected: {relative_path}. Consider flattening package structure."
                )

        return issues

    async def _perform_ai_code_review(self, project_path: Path, structure: dict[str, Any]) -> dict[str, Any]:
        """Perform AI-powered code review using Claude Sonnet 4."""

        # Gather code samples for review (limit to prevent token overflow)
        code_samples = []
        py_files = list(project_path.rglob("*.py"))[:20]  # Review up to 20 files

        for py_file in py_files:
            try:
                with open(py_file, encoding="utf-8") as f:
                    content = f.read()
                    if len(content) < 10000:  # Skip very large files
                        code_samples.append(
                            {
                                "file": str(py_file.relative_to(project_path)),
                                "content": content[:5000],  # Truncate for review
                            }
                        )
            except Exception:
                continue

        # Create comprehensive review prompt
        review_prompt = f"""
        You are an expert code reviewer performing automated analysis for an AWS Labs MCP server project.

        **Project Analysis:**
        - Type: {structure["project_type"]}
        - Language: {structure["primary_language"]}
        - Files: {structure["file_count"]} Python files
        - Has tests: {structure["has_tests"]}
        - Dependencies: {", ".join(structure["dependencies"])}

        **Review Focus Areas:**
        1. **Security**: Check for credential exposure, injection vulnerabilities, unsafe practices
        2. **AWS Best Practices**: Verify proper AWS SDK usage, error handling, resource management
        3. **Code Quality**: Assess maintainability, readability, type safety
        4. **Performance**: Identify bottlenecks, inefficient patterns, resource leaks
        5. **Testing**: Evaluate test coverage, test quality, edge case handling
        6. **Documentation**: Check docstrings, comments, API documentation

        **Code Samples to Review:**
        {json.dumps(code_samples[:10], indent=2)}

        **Required Output Format:**
        Provide a JSON response with:
        {{
            "critical": ["Critical security/functionality issues"],
            "warnings": ["Important issues that should be addressed"],
            "suggestions": ["Improvement recommendations"],
            "security_score": 0-100,
            "quality_score": 0-100,
            "maintainability_score": 0-100,
            "summary": "Overall assessment and key recommendations"
        }}

        **Focus on:**
        - AWS CloudWAN/networking specific best practices
        - MCP server implementation patterns
        - Security vulnerabilities and credential handling
        - Performance optimizations for network analysis tools
        - Error handling and recovery patterns
        """

        try:
            response = await self.client.post(
                f"{self.endpoint}/chat/completions",
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are an expert code reviewer specializing in AWS services, Python development, and security best practices. Provide detailed, actionable feedback in JSON format.",
                        },
                        {"role": "user", "content": review_prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 4000,
                },
            )

            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]

                # Parse JSON response
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    # Fallback if AI doesn't return valid JSON
                    return {
                        "critical": [],
                        "warnings": ["AI review parsing failed"],
                        "suggestions": [content[:500] + "..." if len(content) > 500 else content],
                        "summary": "AI code review completed with parsing issues",
                    }
            else:
                return {
                    "critical": [],
                    "warnings": [f"AI review failed: HTTP {response.status_code}"],
                    "suggestions": [],
                    "summary": "AI code review unavailable",
                }

        except Exception as e:
            return {
                "critical": [],
                "warnings": [f"AI review error: {str(e)}"],
                "suggestions": [],
                "summary": "AI code review failed due to connection issues",
            }

    async def _validate_documentation(self, project_path: Path) -> list[str]:
        """Validate documentation consistency and completeness."""
        issues = []

        # Check for README
        readme_path = project_path / "README.md"
        if not readme_path.exists():
            issues.append("DOCUMENTATION: Missing README.md file")
        else:
            # Use AI to validate README quality
            try:
                with open(readme_path) as f:
                    readme_content = f.read()

                doc_review = await self._ai_documentation_review(readme_content)
                issues.extend(doc_review)

            except Exception as e:
                issues.append(f"DOCUMENTATION: Failed to analyze README.md: {e}")

        # Check for API documentation
        if (project_path / "docs").exists():
            doc_files = list((project_path / "docs").rglob("*.md"))
            if not doc_files:
                issues.append("DOCUMENTATION: docs/ directory exists but contains no markdown files")

        # Check docstring coverage
        py_files = list(project_path.rglob("*.py"))[:10]  # Sample files
        missing_docstrings = 0

        for py_file in py_files:
            try:
                with open(py_file) as f:
                    content = f.read()

                # Simple heuristic: check if functions have docstrings
                function_matches = re.findall(r"def\s+\w+\([^)]*\):", content)
                docstring_matches = re.findall(r'""".*?"""', content, re.DOTALL)

                if len(function_matches) > len(docstring_matches):
                    missing_docstrings += 1

            except Exception:
                continue

        if missing_docstrings > len(py_files) // 2:
            issues.append(
                f"DOCUMENTATION: {missing_docstrings} files missing docstrings. "
                f"Add comprehensive docstrings to public functions and classes."
            )

        return issues

    async def _ai_documentation_review(self, readme_content: str) -> list[str]:
        """Use AI to review documentation quality."""
        if len(readme_content) < 100:
            return ["DOCUMENTATION: README.md is too brief. Add installation, usage, and examples."]

        prompt = f"""
        Review this README.md for completeness and accuracy:

        {readme_content[:2000]}

        Check for:
        1. Clear project description and purpose
        2. Installation instructions
        3. Usage examples with code
        4. API documentation or links
        5. Contributing guidelines
        6. License information

        Return only a JSON array of issues found, like:
        ["Missing installation section", "No usage examples provided"]
        """

        try:
            response = await self.client.post(
                f"{self.endpoint}/chat/completions",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": 1000,
                },
            )

            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]

                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    return ["DOCUMENTATION: AI review parsing failed"]
            else:
                return []

        except Exception:
            return []

    def _calculate_score(
        self, code_review: dict[str, Any], naming_issues: list[str], structure_issues: list[str], doc_issues: list[str]
    ) -> int:
        """Calculate overall project score (0-100)."""

        base_score = 100

        # Deduct for critical issues
        critical_count = len(code_review.get("critical", []))
        base_score -= critical_count * 20

        # Deduct for warnings
        warning_count = len(code_review.get("warnings", []))
        base_score -= warning_count * 10

        # Deduct for naming issues
        base_score -= len(naming_issues) * 5

        # Deduct for structure issues
        base_score -= len(structure_issues) * 8

        # Deduct for documentation issues
        base_score -= len(doc_issues) * 3

        # Use AI-provided scores if available
        if "security_score" in code_review:
            security_weight = 0.4
            quality_weight = 0.3
            maintainability_weight = 0.3

            ai_score = (
                code_review.get("security_score", 80) * security_weight
                + code_review.get("quality_score", 80) * quality_weight
                + code_review.get("maintainability_score", 80) * maintainability_weight
            )

            # Blend manual deductions with AI assessment
            base_score = int((base_score * 0.6) + (ai_score * 0.4))

        return max(0, min(100, base_score))

    async def generate_review_report(self, result: ReviewResult, output_path: Path) -> None:
        """Generate comprehensive review report."""

        report = f"""# Automated Code Review Report

## Overall Score: {result.overall_score}/100

{"🎉 EXCELLENT" if result.overall_score >= 90 else "✅ GOOD" if result.overall_score >= 75 else "⚠️ NEEDS IMPROVEMENT" if result.overall_score >= 60 else "❌ CRITICAL ISSUES"}

## Summary
{result.summary}

## Critical Issues ({len(result.critical_issues)})
"""

        if result.critical_issues:
            for issue in result.critical_issues:
                report += f"- 🔴 {issue}\n"
        else:
            report += "- ✅ No critical issues found\n"

        report += f"""
## Warnings ({len(result.warnings)})
"""

        if result.warnings:
            for warning in result.warnings:
                report += f"- ⚠️ {warning}\n"
        else:
            report += "- ✅ No warnings\n"

        report += f"""
## File Naming Issues ({len(result.file_naming_issues)})
"""

        if result.file_naming_issues:
            for issue in result.file_naming_issues:
                report += f"- 📝 {issue}\n"
        else:
            report += "- ✅ File naming follows best practices\n"

        report += f"""
## Directory Structure Issues ({len(result.structure_issues)})
"""

        if result.structure_issues:
            for issue in result.structure_issues:
                report += f"- 📁 {issue}\n"
        else:
            report += "- ✅ Directory structure follows best practices\n"

        report += f"""
## Documentation Issues ({len(result.documentation_issues)})
"""

        if result.documentation_issues:
            for issue in result.documentation_issues:
                report += f"- 📖 {issue}\n"
        else:
            report += "- ✅ Documentation is comprehensive\n"

        report += f"""
## Suggestions ({len(result.suggestions)})
"""

        if result.suggestions:
            for suggestion in result.suggestions:
                report += f"- 💡 {suggestion}\n"
        else:
            report += "- ✅ No additional suggestions\n"

        report += """
## Next Steps

### Critical Issues (Fix Immediately)
- Address all critical security and functionality issues
- Ensure no credentials are exposed in code

### High Priority
- Resolve file naming issues using proper git workflow
- Clean up directory structure
- Fix major warnings

### Recommended Improvements
- Implement suggested enhancements
- Improve test coverage
- Enhance documentation

---
*Generated by AWS Labs CI Pipeline - Automated Code Review*
"""

        # Write report
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(report)

    async def close(self) -> None:
        """Cleanup resources."""
        await self.client.aclose()


async def run_automated_review(settings: Settings, project_path: Path, logger) -> int:
    """Run the complete automated code review process."""

    logger.info("🤖 Starting automated code review with Claude Sonnet 4")

    reviewer = CodeReviewer()

    try:
        # Perform review
        result = await reviewer.review_project(project_path, settings)

        # Generate report
        report_path = settings.reports_dir / "code-review-report.md"
        await reviewer.generate_review_report(result, report_path)

        # Log results
        logger.info(f"📊 Review Score: {result.overall_score}/100")

        if result.critical_issues:
            logger.error(f"🔴 {len(result.critical_issues)} critical issues found")
            for issue in result.critical_issues[:3]:  # Show first 3
                logger.error(f"   - {issue[:100]}...")

        if result.file_naming_issues:
            logger.warning(f"📝 {len(result.file_naming_issues)} file naming issues")

        if result.structure_issues:
            logger.warning(f"📁 {len(result.structure_issues)} structure issues")

        logger.success(f"📄 Review report generated: {report_path}")

        # Return exit code based on critical issues
        return 1 if result.critical_issues else 0

    except Exception as e:
        logger.error(f"Automated review failed: {e}")
        return 1
    finally:
        await reviewer.close()
