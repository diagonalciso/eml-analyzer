"""PyInstaller entry point — absolute imports only."""
import sys
from eml_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
