import os
import time
import json
from dotenv import load_dotenv
from utils import logger, print_agent_message, print_tool_output, print_system
from tools import AVAILABLE_TOOLS, get_tool_definitions, GEMINI_TOOLS

# Lazy imports to avoid fatal errors if dependencies are missing during switch
try:
    import google.generativeai as genai
    from google.api_core import exceptions as google_exceptions
except ImportWarning:
    pass

try:
    from openai import OpenAI, OpenAIError
except ImportError:
    pass

# Load environment variables
load_dotenv()

SYSTEM_PROMPT = """You are the **PentPython Unified Security AI**, an all-in-one elite defensive and offensive security suite. You embody 6 specialized personas concurrently:

1. **🛡️ Security Engineer**: Architecture, DevSecOps, and cloud compliance.
2. **⚔️ Red Teamer**: APT simulation and adversarial attack path modeling.
3. **🔍 Pentester**: Continuous vulnerability assessment and exploit validation.
4. **🦅 Threat Hunter**: Anomaly detection and zero-day pattern recognition.
5. **🌑 Dark Web Monitor**: Leaked data scanning and threat intelligence.
6. **🚨 SOC Analyst**: 24/7 log correlation and automated incident response.

**CORE RULES:**
1. **MULTI-AGENT COLLABORATION**: For any request, use the combined expertise of all 6 agents.
2. **ZERO FLUFF**: Be technical, concise, and provide actionable security intelligence.
3. **TOOL ORIENTED**: Rely on your specialized tools to validate theories.
4. **REPORTING**: Use `save_pdf_report` for final outcomes with remediation prioritizations.

**SPECIALIZED TOOLS:**
- **ENGINEERING**: `cloud_audit` (Cloud configuration), `ci_cd_scanner` (Pipeline security).
- **OFFENSIVE**: `injection_scanner`, `attack_path_mapper` (Red Teaming), `ssrf_tester`.
- **RECON**: `subdomain_finder`, `dir_scanner`, `port_scanner`, `tech_detect`, `whois_lookup`.
- **DEFENSIVE**: `log_analyzer` (SOC/Hunting), `dark_web_scanner` (Intel).
- **ANALYSIS**: `auth_tester`, `access_control_tester`, `ssl_scanner`, `dns_lookup`.

**RESPONSE PROTOCOL (Unified Workflow):**
1. **INTEL**: Use RECON & INTEL tools to map the target/environment.
2. **VULN**: Apply ENGINEERING & PENTEST tools to hunt for weaknesses.
3. **ADVERSARY**: Emulate RED TEAM logic to find lateral movement paths.
4. **RESPONSE**: Use SOC logic to propose defensive controls and generate the PDF report.

Always maintain a professional, elite security posture.
"""





class FatalAPIError(Exception):
    pass

class OpenAIPentAgent:
    def __init__(self, api_key):
        self.client = OpenAI(api_key=api_key)
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.tools = get_tool_definitions()

    def run(self, user_input: str):
        self.messages.append({"role": "user", "content": user_input})
        
        try:
            # Simple loop for tool calls (max 5)
            for _ in range(5):
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=self.messages,
                    tools=self.tools,
                    tool_choice="auto"
                )
                message = response.choices[0].message

                if message.content:
                    print_agent_message(message.content)
                    self.messages.append(message)

                if message.tool_calls:
                    if not message.content:
                        self.messages.append(message)
                    
                    for tool_call in message.tool_calls:
                        func_name = tool_call.function.name
                        args = json.loads(tool_call.function.arguments)
                        
                        print_system(f"Executing: {func_name}({args})")
                        tool_instance = AVAILABLE_TOOLS.get(func_name)
                        result = tool_instance.execute(**args) if tool_instance else f"Error: {func_name} not found"
                        
                        print_tool_output(func_name, result)
                        
                        self.messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": func_name,
                            "content": result
                        })
                else:
                    break

        except Exception as e:
            logger.error(f"OpenAI Error: {e}")
            raise FatalAPIError(f"OpenAI Error: {e}")

class GeminiPentAgent:
    def __init__(self, api_key):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            model_name='gemini-1.5-flash',
            tools=GEMINI_TOOLS,
            system_instruction=SYSTEM_PROMPT
        )
        self.chat = self.model.start_chat(enable_automatic_function_calling=True)

    def run(self, user_input: str):
        retries = 3
        delay = 5
        for attempt in range(retries):
            try:
                response = self.chat.send_message(user_input)
                print_agent_message(response.text)
                return
            except google_exceptions.ResourceExhausted as e:
                if attempt < retries - 1:
                    print_system(f"Rate limit hit. Waiting {delay}s...")
                    time.sleep(delay)
                    delay *= 2
                else:
                    raise FatalAPIError("Gemini Quota Exceeded.")
            except Exception as e:
                 # Catch other google exceptions or general errors
                 if "404" in str(e) or "401" in str(e):
                      raise FatalAPIError(f"Gemini API Error: {e}")
                 print_agent_message(f"Error: {e}", style="bold red")
                 return

class MockPentAgent:
    def __init__(self):
        print_system("WARNING: Running in SIMULATION MODE.")

    def run(self, user_input: str):
        # Very simple heuristic to extract a target (domain or IP)
        user_input_lower = user_input.lower()
        
        target = "localhost"
        ports = "80-100"
        
        if "scan" in user_input_lower:
            # Look for something that looks like a target
            # Heuristic: find the part after 'scan' or look for any word with a '.'
            words = user_input.split()
            for word in words:
                clean_word = word.strip().strip("'\"")
                if "." in clean_word or clean_word == "localhost":
                    # Remove http/https if present
                    target = clean_word.replace("https://", "").replace("http://", "").split("/")[0]
                    break
            
            print_system(f"Simulating: port_scanner(target='{target}', ports='{ports}')")
            result = AVAILABLE_TOOLS["port_scanner"].execute(target, ports)
            print_tool_output("port_scanner", result)
            print_agent_message(f"Security Scan Report for {target}:\n\n{result}")
            
        elif "read" in user_input_lower or "file" in user_input_lower:
             # Look for a path
             words = user_input.split()
             path = "requirements.txt"
             for word in words:
                 if "." in word and "/" in word or "\\" in word or "requirements" in word:
                     path = word.strip().strip("'\"")
                     break
                     
             print_system(f"Simulating: file_inspect(path='{path}')")
             result = AVAILABLE_TOOLS["file_inspect"].execute(path)
             print_tool_output("file_inspect", result)
             print_agent_message(f"File Inspection Result for {path}:\n\n{result}")

        elif "report" in user_input_lower:
             # Look for a target
             target = "example.com"
             words = user_input.split()
             for word in words:
                 if "." in word and not word.startswith("-"):
                     target = word.strip().strip("'\"")
                     break
             
             print_system(f"Simulating: save_pdf_report(target='{target}')")
             result = AVAILABLE_TOOLS["save_pdf_report"].execute(target)
             print_agent_message(f"### 📄 Security Report Ready\n\n{result}")


        else:
            print_agent_message("I am currently in **SIMULATION MODE** (no API key found).\n\nI can execute simple commands for you like:\n- `scan target.com` (Extract domain & scan ports)\n- `report target.com` (Generate a sample PDF report)\n- `read file.txt` (Extract path & read file)\n\nTo get full AI logic, please provide a `GEMINI_API_KEY` or `OPENAI_API_KEY`.")


def get_agent():
    """Factory to return the best available agent."""
    openai_key = os.getenv("OPENAI_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY")

    if openai_key:
        print_system("Using Provider: OpenAI")
        return OpenAIPentAgent(openai_key)
    elif gemini_key:
        print_system("Using Provider: Google Gemini")
        return GeminiPentAgent(gemini_key)
    else:
        print_system("No API keys found. Using Mock Provider.")
        return MockPentAgent()
