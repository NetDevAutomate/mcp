"""Error path coverage tests for CloudWAN MCP Server."""

import ast
from pathlib import Path
from typing import Dict, List

import pytest


class TestErrorPathCoverage:
    """Test error path coverage and exception handling."""

    def get_python_files(self) -> List[Path]:
        """Get all Python files in the project."""
        project_root = Path(__file__).parent.parent
        python_files = []

        for pattern in ["awslabs/**/*.py"]:
            python_files.extend(project_root.glob(pattern))

        return [f for f in python_files if "__pycache__" not in str(f)]

    def find_exception_handlers(self, file_path: Path) -> List[Dict]:
        """Find all exception handlers in a Python file."""
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read())
            except SyntaxError:
                return []

        handlers = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                handler_info = {
                    "file": str(file_path),
                    "line": node.lineno,
                    "exception_type": None,
                    "has_specific_type": False,
                }

                if node.type:
                    if isinstance(node.type, ast.Name):
                        handler_info["exception_type"] = node.type.id
                        handler_info["has_specific_type"] = True
                    elif isinstance(node.type, ast.Tuple):
                        types = []
                        for elt in node.type.elts:
                            if isinstance(elt, ast.Name):
                                types.append(elt.id)
                        handler_info["exception_type"] = types
                        handler_info["has_specific_type"] = True
                else:
                    # Bare except clause
                    handler_info["exception_type"] = "bare_except"
                    handler_info["has_specific_type"] = False

                handlers.append(handler_info)

        return handlers

    def test_no_bare_except_clauses_remain(self):
        """Test that no bare except clauses remain in the codebase."""
        python_files = self.get_python_files()
        bare_except_found = []

        for py_file in python_files:
            handlers = self.find_exception_handlers(py_file)
            for handler in handlers:
                if not handler["has_specific_type"]:
                    bare_except_found.append(f"{handler['file']}:{handler['line']} - bare except clause")

        if bare_except_found:
            error_msg = "Bare except clauses found (should be replaced with specific exceptions):\n"
            error_msg += "\n".join(bare_except_found)
            pytest.fail(error_msg)
