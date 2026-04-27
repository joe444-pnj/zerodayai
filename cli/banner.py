"""
cli/banner.py — ZeroDay AI ASCII Banner
"""
from __future__ import annotations
from rich.console import Console
from rich.text import Text

console = Console()

BANNER = r"""
 ______              ____              ___    ____
|__  / ___ _ __ ___|  _ \  __ _ _  _|_ _|  / ___|
  / / / _ \ '__/ _ \ | | |/ _` | | | || |  \___ \
 / /_|  __/ | | (_) | |_| | (_| | |_| || |   ___) |
/____|\___|_|  \___/|____/ \__,_|\__, |___|  |____/
                                  |___/
"""

TAGLINE = "  ⚡ Autonomous Vulnerability Research Agent  |  Powered by Ollama LLM"
VERSION = "v1.1.0-enhanced"


def print_banner(model_name: str = "") -> None:
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(f"[dim]{TAGLINE}[/dim]")
    model_str = f"  Model: [bold cyan]{model_name}[/bold cyan]" if model_name else ""
    version_str = f"  [dim]{VERSION}[/dim]"
    console.print(f"{version_str}{model_str}")
    console.print()
