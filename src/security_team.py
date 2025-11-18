"""
Security Agent Team Implementation using Agno
Based on crewAI hierarchical agent architecture for security testing.
"""

from typing import Optional
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.team.team import Team
from prompts import *
from tools import SECURITY_TOOLS


class SecurityAgentTeam:
    """
    Multi-agent security testing team with hierarchical structure.
    Manager agent delegates tasks to specialized security agents.
    """
    
    def __init__(self, model_name: str = "gpt-4o-mini"):
        """Initialize the security agent team."""
        self.model_name = model_name
        self.manager = None
        self.team = None
        self._create_agents()
        self._create_team()
    
    def _create_agents(self):
        """Create all specialized security agents."""
        
        # Manager Agent
        self.manager_agent = Agent(
            name="Security Manager",
            role="Security Assessment Coordinator",
            model=OpenAIChat(id=self.model_name),
            instructions=[
                THOUGHT_ROUTER_MANAGER_AGENT_PROMPT,
                "Delegate tasks to specialist agents based on their expertise",
                "Coordinate between multiple agents for comprehensive assessments",
            ],
        )
        
        # Android Security Agent
        self.android_agent = Agent(
            name="Android SAST Agent",
            role="Android Security Specialist",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                ANDROID_SAST_AGENT_PROMPT,
                "Analyze Android applications for security vulnerabilities",
            ],
        )
        
        # Blue Team Agent
        self.blue_team_agent = Agent(
            name="Blue Team Agent",
            role="Defense and Detection Specialist",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                BLUETEAM_AGENT_PROMPT,
                "Focus on defensive security measures and threat detection",
            ],
        )
        
        # Bug Bounty Agent
        self.bug_bounty_agent = Agent(
            name="Bug Bounty Hunter",
            role="Web Vulnerability Researcher",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                BUG_BOUNTY_AGENT_PROMPT,
                "Identify and report web application vulnerabilities",
            ],
        )
        
        # Coding Agent
        self.coding_agent = Agent(
            name="Security Coding Agent",
            role="Python Security Tool Developer",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                CODE_AGENT,
                "Write secure Python code for security tools and exploits",
            ],
        )
        
        # DFIR Agent
        self.dfir_agent = Agent(
            name="DFIR Specialist",
            role="Digital Forensics and Incident Response",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                DFIR_AGENT_PROMPT,
                "Investigate security incidents and analyze digital evidence",
            ],
        )
        
        # Memory Analysis Agent
        self.memory_agent = Agent(
            name="Memory Analysis Agent",
            role="Runtime Memory Specialist",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                MEMPORY_ANALYSIS_PROMPT,
                "Analyze process memory and runtime behavior",
            ],
        )
        
        # Network Security Agent
        self.network_agent = Agent(
            name="Network Security Analyst",
            role="Network Traffic Analysis",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                NETWORK_ANALYSER_PROMPT,
                "Monitor and analyze network traffic for security threats",
            ],
        )
        
        # Red Team Agent
        self.red_team_agent = Agent(
            name="Red Team Operator",
            role="Offensive Security Specialist",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                RED_TEAM_AGENT_PROMPT,
                "Simulate adversary tactics and identify security weaknesses",
            ],
        )
        
        # Replay Attack Agent
        self.replay_attack_agent = Agent(
            name="Replay Attack Specialist",
            role="Network Replay Expert",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                REPlAY_ATTACK_AGENT_PROMPT,
                "Capture and replay network traffic for testing",
            ],
        )
        
        # Reporting Agent
        self.reporting_agent = Agent(
            name="Security Reporting Agent",
            role="Security Report Generator",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                REPORTING_AGENT_PROMPT,
                "Create comprehensive security assessment reports",
            ],
        )
        
        # Vulnerability Triage Agent
        self.triage_agent = Agent(
            name="Vulnerability Triage Agent",
            role="Security Finding Validator",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                TRIAGER_AGENT_PROMPT,
                "Verify and validate security vulnerabilities",
            ],
        )
        
        # Reverse Engineering Agent
        self.reverse_engineering_agent = Agent(
            name="Reverse Engineering Agent",
            role="Binary Analysis Specialist",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                REVERSE_ENGINEERING_AGENT_PROMPT,
                "Analyze binaries and reverse engineer software",
            ],
        )
        
        # Sub-GHz SDR Agent
        self.subghz_agent = Agent(
            name="Sub-GHz SDR Agent",
            role="RF Security Specialist",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                SUBGHZ_AGENT_PROMPT,
                "Analyze sub-GHz radio frequency signals",
            ],
        )
        
        # WiFi Security Agent
        self.wifi_agent = Agent(
            name="WiFi Security Agent",
            role="Wireless Security Tester",
            model=OpenAIChat(id=self.model_name),
            tools=SECURITY_TOOLS,
            instructions=[
                WIFI_SECURITY_AGENT_PROMPT,
                "Test wireless network security",
            ],
        )
    
    def _create_team(self):
        """Create the hierarchical security team."""
        self.team = Team(
            name="Elite Security Assessment Team",
            model=OpenAIChat(id=self.model_name),
            respond_directly=True,
            members=[
                self.android_agent,
                self.blue_team_agent,
                self.bug_bounty_agent,
                self.coding_agent,
                self.dfir_agent,
                self.memory_agent,
                self.network_agent,
                self.red_team_agent,
                self.replay_attack_agent,
                self.reporting_agent,
                self.triage_agent,
                self.reverse_engineering_agent,
                self.subghz_agent,
                self.wifi_agent,
            ],
            markdown=True,
            instructions=[
                "You are an elite security assessment team with specialized agents.",
                "The manager coordinates tasks and delegates to appropriate specialists.",
                "Each agent has deep expertise in their security domain.",
                "Work together to provide comprehensive security assessments.",
                "Always prioritize thorough analysis and accurate reporting.",
            ],
            show_members_responses=True,
        )
    
    def assess(self, task_description: str, stream: bool = True):
        """
        Run a security assessment task.
        
        Args:
            task_description: Description of the security task
            stream: Whether to stream the response
        """
        print("=" * 80)
        print("ELITE SECURITY ASSESSMENT TEAM")
        print("=" * 80)
        print(f"\nTask: {task_description}\n")
        print("-" * 80)
        
        if self.team:
            self.team.print_response(task_description, stream=stream)
        
        print("\n" + "=" * 80)
        print("Assessment Complete")
        print("=" * 80)
    
    def get_agent_by_name(self, name: str) -> Optional[Agent]:
        """Get a specific agent by name."""
        agents = {
            "android": self.android_agent,
            "blue_team": self.blue_team_agent,
            "bug_bounty": self.bug_bounty_agent,
            "coding": self.coding_agent,
            "dfir": self.dfir_agent,
            "memory": self.memory_agent,
            "network": self.network_agent,
            "red_team": self.red_team_agent,
            "replay_attack": self.replay_attack_agent,
            "reporting": self.reporting_agent,
            "triage": self.triage_agent,
            "reverse_engineering": self.reverse_engineering_agent,
            "subghz": self.subghz_agent,
            "wifi": self.wifi_agent,
        }
        return agents.get(name.lower())


def main():
    """Example usage of the security agent team."""
    team = SecurityAgentTeam()
    
    # Example task
    task = """
    Analyze the security of a web application at example.com.
    Identify potential vulnerabilities and provide recommendations.
    """
    
    team.assess(task, stream=True)


if __name__ == "__main__":
    main()
