import sys
import os
from agent import get_agent, MockPentAgent
from exceptions import FatalAPIError
from utils import print_system, console

def main():
    agent = get_agent()

    console.rule("[bold blue]PentPython Shell")
    console.print("Type 'exit' to quit.\n")

    while True:
        try:
            user_input = console.input("[bold green]User > [/]")
            if user_input.lower() in ["exit", "quit", "q"]:
                break
            
            if not user_input.strip():
                continue

            try:
                agent.run(user_input)
            except FatalAPIError as e:
                print_system(f"Critical AI Error: {e}")
                print_system("Falling back to SIMULATION MODE automatically.")
                agent = MockPentAgent()
                # Retry the last command with the mock agent? 
                # Maybe better to just let user type again, or run it immediately.
                # Let's run it immediately for smooth UX
                print_system("Retrying with Simulation Agent...")
                agent.run(user_input)

            print() # Newline for readability

        except KeyboardInterrupt:
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/]")

if __name__ == "__main__":
    main()
