import os
import time
import json
from dotenv import load_dotenv
from utils import logger, print_agent_message, print_tool_output, print_system
from tools import AVAILABLE_TOOLS, get_tool_definitions, GEMINI_TOOLS
from exceptions import FatalAPIError

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






class PentAgentBase:
    def __init__(self):
        self.logs = []

    def log(self, message: str, type="system"):
        if type == "system":
            self.logs.append(f"[SYSTEM] {message}")
        elif type == "tool":
            self.logs.append(f"[TOOL] {message}")
        elif type == "agent":
            self.logs.append(message)

    def get_logs(self) -> str:
        return "\n".join(self.logs)

class OpenAIPentAgent(PentAgentBase):
    def __init__(self, api_key):
        super().__init__()
        self.client = OpenAI(api_key=api_key)
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.tools = get_tool_definitions()

    def run(self, user_input: str):
        self.logs = [] # Reset for new run
        self.messages.append({"role": "user", "content": user_input})
        
        try:
            for _ in range(5):
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=self.messages,
                    tools=self.tools,
                    tool_choice="auto"
                )
                message = response.choices[0].message

                if message.content:
                    self.log(message.content, "agent")
                    self.messages.append(message)

                if message.tool_calls:
                    if not message.content:
                        self.messages.append(message)
                    
                    for tool_call in message.tool_calls:
                        func_name = tool_call.function.name
                        args = json.loads(tool_call.function.arguments)
                        
                        self.log(f"Executing: {func_name}({args})", "system")
                        tool_instance = AVAILABLE_TOOLS.get(func_name)
                        result = tool_instance.execute(**args) if tool_instance else f"Error: {func_name} not found"
                        
                        self.log(result, "tool")
                        
                        self.messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": func_name,
                            "content": result
                        })
                else:
                    break
            return self.get_logs()
        except Exception as e:
            raise FatalAPIError(f"OpenAI Error: {e}")

class GeminiPentAgent(PentAgentBase):
    def __init__(self, api_key):
        super().__init__()
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            model_name='gemini-1.5-flash',
            tools=GEMINI_TOOLS,
            system_instruction=SYSTEM_PROMPT
        )
        self.chat = self.model.start_chat(enable_automatic_function_calling=True)

    def run(self, user_input: str):
        self.logs = []
        retries = 3
        delay = 5
        for attempt in range(retries):
            try:
                response = self.chat.send_message(user_input)
                # Gemini auto-calls tools, we need to extract the final text
                self.log(response.text, "agent")
                return self.get_logs()
            except google_exceptions.ResourceExhausted:
                if attempt < retries - 1:
                    time.sleep(delay)
                    delay *= 2
                else:
                    raise FatalAPIError("Gemini Quota Exceeded.")
            except Exception as e:
                raise FatalAPIError(f"Gemini Error: {e}")

class MockPentAgent(PentAgentBase):
    def __init__(self):
        super().__init__()
        self.log("Running in SIMULATION MODE.", "system")

    def run(self, user_input: str):
        self.logs = []
        user_input_lower = user_input.lower()
        
        if "scan" in user_input_lower:
            target = "example.com"
            self.log(f"Simulating: port_scanner(target='{target}')", "system")
            result = AVAILABLE_TOOLS["port_scanner"].execute(target, "80,443")
            self.log(result, "tool")
            self.log(f"Security Scan Report for {target}:\n\n{result}", "agent")
            
        elif "report" in user_input_lower:
            target = "example.com"
            self.log(f"Simulating: save_pdf_report(target='{target}')", "system")
            result = AVAILABLE_TOOLS["save_pdf_report"].execute(target)
            self.log(f"### 📄 Security Report Ready\n\n{result}", "agent")

        else:
            self.log("SIMULATION MODE: Try 'scan target.com' or 'report target.com'", "agent")
            
        return self.get_logs()

def get_agent():
    openai_key = os.getenv("OPENAI_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY")

    if openai_key:
        return OpenAIPentAgent(openai_key)
    elif gemini_key:
        return GeminiPentAgent(gemini_key)
    return MockPentAgent()

