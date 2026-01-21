import logging
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.text import Text

# Initialize Rich Console
console = Console()

def setup_logging(level="INFO"):
    """
    Sets up the logging configuration using RichHandler.
    """
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )
    log = logging.getLogger("rich")
    return log

logger = setup_logging()

def print_agent_message(message: str, style="bold cyan"):
    """Prints a message from the agent in a panel."""
    console.print(Panel(message, title="PentAgent", style=style, border_style=style))

def print_tool_output(tool_name: str, output: str):
    """Prints output from a tool."""
    console.print(Panel(output, title=f"Tool: {tool_name}", style="green", border_style="green"))

def print_error(message: str):
    """Prints an error message."""
    console.print(Panel(message, title="Error", style="bold red", border_style="red"))

def print_system(message: str):
    """Prints a system message."""
    console.print(Text(f"[SYSTEM] {message}", style="dim"))
