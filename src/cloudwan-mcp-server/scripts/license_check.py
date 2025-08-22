# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Models package for CloudWAN MCP Server."""
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Backup server implementation for AWS CloudWAN MCP Server."""

# Corrected server_backup.py with proper class definition
class ServerBackup:
#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test runner for CloudWAN MCP Server tests."""
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: check-merge-conflict
      - id: check-yaml
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]
        exclude: tests/security/test_error_handler.py
      - id: check-json
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: mixed-line-ending
        args: ["--fix=lf"]

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.6
    hooks:
      - id: ruff
        args: ["--fix"]
      - id: ruff-format

  - repo: local
    hooks:
      - id: license-headers
        name: License Header Check
        entry: python scripts/license_check.py
        language: python
        files: \.(py|sh|json|yaml|yml|md|toml)$
        pass_filenames: false
        always_run: true
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Original server implementation for AWS CloudWAN MCP Server."""

# Corrected server_original.py with proper class implementation
class OriginalServerImplementation:
 Tuple[bool, str]:
    """Check if file has proper Apache 2.0 license header."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Skip empty files
        if not lines:
            return True, "Empty file"

        # Check if file starts with shebang
        start_line = 0
        if lines[0].startswith('#!'):
            start_line = 1

        # Check if we have enough lines for the header
        if len(lines) < start_line + len(EXPECTED_HEADER_LINES):
            return False, "File too short for license header"

        # Check each line of the expected header
        for i, expected_line in enumerate(EXPECTED_HEADER_LINES):
            actual_line = lines[start_line + i].rstrip()
            if actual_line != expected_line:
                return False, f"Line {start_line + i + 1}: Expected '{expected_line}', got '{actual_line}'"

        return True, "License header valid"

    except Exception as e:
        return False, f"Error reading file: {str(e)}"


def find_python_files(root_dir: Path) -> List[Path]:
    """Find all Python files that should have license headers."""
    python_files = []

    # Exclude certain directories
    exclude_dirs = {'.git', '__pycache__', '.pytest_cache', 'node_modules', '.venv', 'venv'}

    for py_file in root_dir.rglob('*.py'):
        # Skip if in excluded directory
        if any(excl in py_file.parts for excl in exclude_dirs):
            continue

        # Skip __init__.py files that are just imports
        if py_file.name == '__init__.py':
            try:
                with open(py_file, 'r') as f:
                    content = f.read().strip()
                    # Skip very minimal __init__.py files
                    if len(content) < 100 and ('__all__' in content or 'import' in content):
                        continue
            except:
                pass

        python_files.append(py_file)

    return python_files


def main() -> int:
    """Main license check function."""
    root_dir = Path.cwd()

    # Find all Python files
    python_files = find_python_files(root_dir)

    if not python_files:
        print("No Python files found for license check")
        return 0

    print(f"Checking license headers in {len(python_files)} Python files...")

    missing_headers = []
    invalid_headers = []

    for py_file in python_files:
        is_valid, message = check_license_header(py_file)

        if not is_valid:
            if "too short" in message.lower() or "error reading" in message.lower():
                missing_headers.append((py_file, message))
            else:
                invalid_headers.append((py_file, message))

    # Report results
    if missing_headers:
        print(f"\n❌ {len(missing_headers)} files missing license headers:")
        for file_path, reason in missing_headers[:10]:  # Show first 10
            print(f"  - {file_path}: {reason}")
        if len(missing_headers) > 10:
            print(f"  ... and {len(missing_headers) -
<chatName="Add Apache 2.0 license header to server_original.py"/>

<Plan>
I need to add the Apache 2.0 license header at the very beginning of the file, before the existing comment and class definition. The license header should include the copyright notice, license text, and a docstring describing the module purpose.
</Plan>

<file path="/Users/taylaand/code/mcp/src/cloudwan-mcp-server/awslabs/cloudwan_mcp_server/server_original.py" action="modify">
