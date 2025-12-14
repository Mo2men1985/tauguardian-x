

import subprocess
import os
import re
from typing import Tuple


def run_tests_in_sandbox(
    test_file_path: str,
    project_root: str,
    docker_image: str = "python:3.9-slim",
    timeout: int = 30,
) -> Tuple[int, str]:
    """
    Run pytest inside a Docker container to sandbox untrusted code.

    Args:
        test_file_path: Absolute path to the test file.
        project_root: Absolute path to the directory containing code + tests.
        docker_image: Docker image to use.
        timeout: Timeout in seconds.

    Returns:
        (exit_code, output_string)
    """
    test_file_path = os.path.abspath(test_file_path)
    project_root = os.path.abspath(project_root)
    rel_test_path = os.path.relpath(test_file_path, project_root)

    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{project_root}:/app",
        "-w",
        "/app",
        docker_image,
        "bash",
        "-c",
        f"pip install pytest > /dev/null 2>&1 && pytest -q {rel_test_path}",
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return 124, f"[ERROR] Sandbox execution timed out after {timeout}s"
    except FileNotFoundError:
        return (
        1,
        "[ERROR] Docker executable not found. Install Docker from https://docs.docker.com/get-docker/ " \
        "or disable sandboxing by unsetting TG_SANDBOX or setting TG_SANDBOX=0.",
    )
    except Exception as e:
        return 1, f"[ERROR] Sandbox failure: {e}"


def parse_pytest_sandbox_output(output: str) -> Tuple[int, int]:
    """
    Parse sandboxed pytest output into (total_tests, failed_tests).
    """
    m = re.search(r"(\d+)\s+passed(?:,\s+(\d+)\s+failed)?", output)
    if m:
        passed = int(m.group(1))
        failed = int(m.group(2)) if m.group(2) else 0
        return passed + failed, failed

    m = re.search(r"FAILED.*failures=(\d+)", output)
    if m:
        failed = int(m.group(1))
        m2 = re.search(r"(\d+)\s+passed", output)
        passed = int(m2.group(1)) if m2 else 0
        return passed + failed, failed

    if "SyntaxError" in output or "IndentationError" in output:
        return 1, 1

    return 1, 1


