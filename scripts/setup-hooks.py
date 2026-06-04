#!/usr/bin/env python3
"""setup-hooks.py — Installs Git hooks that run the Claude project hooks.

This script sets up local Git hooks under .git/hooks/ to execute the safety
and hygiene checks (like branch checking and spec-coverage verification)
which are otherwise only executed inside the Claude Code agent environment.
"""

import os
import sys
import stat
from pathlib import Path

PRE_COMMIT_CONTENT = """#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

def get_git_command():
    # Attempt to read the parent process (git) cmdline.
    ppid = os.getppid()
    try:
        cmdline_file = Path(f"/proc/{ppid}/cmdline")
        if cmdline_file.exists():
            args = cmdline_file.read_bytes().split(b'\\x00')
            # Decode arguments
            decoded_args = []
            for arg in args:
                if arg:
                    try:
                        decoded_args.append(arg.decode('utf-8'))
                    except UnicodeDecodeError:
                        decoded_args.append(arg.decode('latin1'))
            return " ".join(decoded_args)
    except Exception:
        pass
    # Fallback if proc fs isn't accessible
    return "git commit"

def run_hook(script_path, command):
    # Construct the JSON payload required by the Claude hook scripts
    payload = {
        "tool_name": "Bash",
        "tool_input": {
            "command": command
        }
    }
    
    # Run the script, piping payload to stdin
    env = os.environ.copy()
    env["CLAUDE_PROJECT_DIR"] = str(Path(__file__).resolve().parents[2])
    
    proc = subprocess.run(
        [sys.executable, str(script_path)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env
    )
    return proc

def main():
    project_dir = Path(__file__).resolve().parents[2]
    scripts_dir = project_dir / ".claude" / "scripts"
    
    command = get_git_command()
    
    # Pre-tool hooks to run on git commit
    hooks = [
        ("block-no-verify.py", "minimal"),
        ("no-commit-on-main.py", "minimal"),
        ("spec-coverage-check.py", "standard"),
    ]
    
    for hook_name, _ in hooks:
        hook_path = scripts_dir / hook_name
        if not hook_path.exists():
            continue
            
        res = run_hook(hook_path, command)
        if res.returncode != 0:
            # Print the output from the hook and abort the commit
            if res.stderr:
                print(res.stderr.strip(), file=sys.stderr)
            if res.stdout:
                print(res.stdout.strip())
            sys.exit(res.returncode)
            
    sys.exit(0)

if __name__ == "__main__":
    main()
"""

POST_MERGE_CONTENT = """#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

def get_git_command():
    ppid = os.getppid()
    try:
        cmdline_file = Path(f"/proc/{ppid}/cmdline")
        if cmdline_file.exists():
            args = cmdline_file.read_bytes().split(b'\\x00')
            decoded_args = []
            for arg in args:
                if arg:
                    try:
                        decoded_args.append(arg.decode('utf-8'))
                    except UnicodeDecodeError:
                        decoded_args.append(arg.decode('latin1'))
            return " ".join(decoded_args)
    except Exception:
        pass
    return "git merge"

def main():
    project_dir = Path(__file__).resolve().parents[2]
    scripts_dir = project_dir / ".claude" / "scripts"
    
    command = get_git_command()
    hook_path = scripts_dir / "auto-cleanup-merge.py"
    if not hook_path.exists():
        sys.exit(0)
        
    payload = {
        "tool_name": "Bash",
        "tool_input": {
            "command": command
        },
        "tool_response": {
            "interrupted": False,
            "is_error": False
        }
    }
    
    env = os.environ.copy()
    env["CLAUDE_PROJECT_DIR"] = str(project_dir)
    
    # Post-merge cleanup is best-effort, so we run and don't exit with non-zero
    res = subprocess.run(
        [sys.executable, str(hook_path)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env
    )
    
    if res.stderr:
        print(res.stderr.strip(), file=sys.stderr)
    if res.stdout:
        print(res.stdout.strip())
    sys.exit(0)

if __name__ == "__main__":
    main()
"""

def make_executable(path: Path):
    st = path.stat()
    path.chmod(st.st_mode | stat.S_IEXEC)

def main():
    project_dir = Path(__file__).resolve().parents[1]
    hooks_dir = project_dir / ".git" / "hooks"
    
    if not hooks_dir.exists():
        print(f"Error: Git hooks directory not found at {hooks_dir}", file=sys.stderr)
        sys.exit(1)
        
    pre_commit_path = hooks_dir / "pre-commit"
    post_merge_path = hooks_dir / "post-merge"
    
    print(f"Writing {pre_commit_path.relative_to(project_dir)}...")
    pre_commit_path.write_text(PRE_COMMIT_CONTENT, encoding="utf-8")
    make_executable(pre_commit_path)
    
    print(f"Writing {post_merge_path.relative_to(project_dir)}...")
    post_merge_path.write_text(POST_MERGE_CONTENT, encoding="utf-8")
    make_executable(post_merge_path)
    
    print("Git hooks successfully installed!")

if __name__ == "__main__":
    main()
