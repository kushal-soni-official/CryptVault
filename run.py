#!/usr/bin/env python3
"""
CryptVault — Unified entry point for CLI and Web UI.
Works on both Windows and Linux/macOS.
"""
import sys
from pathlib import Path

def print_help():
    print()
    print("  CryptVault - Zero-Trust Encrypted File Storage")
    print("  ================================================")
    print()
    print("  Usage:")
    print("    python run.py cli [args]   Run the Command Line Interface")
    print("    python run.py web          Start the Web UI server")
    print("    python run.py --help       Show this help message")
    print()

def main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    cmd = sys.argv[1].lower()
    project_root = Path(__file__).parent.absolute()
    sys.path.insert(0, str(project_root))

    if cmd == "cli":
        from cryptvault.cli.main import main as cli_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        cli_main()
    elif cmd == "web":
        import uvicorn
        from cryptvault.web.app import app
        print("Starting CryptVault Web UI at http://127.0.0.1:8000")
        uvicorn.run(app, host="127.0.0.1", port=8000)
    elif cmd in ["--help", "-h", "help"]:
        print_help()
    else:
        print(f"Unknown command: {cmd}")
        print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
