"""
Language Routing Example - Demonstrates Agno Team functionality
This example shows how to create a multi-language team that routes questions
to appropriate language-specific agents.
"""

from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.team.team import Team


def create_language_routing_team():
    """Create a team that routes questions based on language."""
    
    english_agent = Agent(
        name="English Agent",
        role="You can only answer in English",
        model=OpenAIChat(id="gpt-4o-mini"),
        instructions=[
            "You must only respond in English",
            "Provide helpful and friendly responses",
        ],
    )

    japanese_agent = Agent(
        name="Japanese Agent",
        role="You can only answer in Japanese",
        model=OpenAIChat(id="gpt-4o-mini"),
        instructions=[
            "You must only respond in Japanese",
            "Provide helpful and friendly responses",
        ],
    )
    
    multi_language_team = Team(
        name="Multi Language Team",
        model=OpenAIChat("gpt-4o-mini"),
        respond_directly=True,
        members=[
            english_agent,
            japanese_agent,
        ],
        markdown=True,
        instructions=[
            "You are a language router that directs questions to the appropriate language agent.",
            "If the user asks in a language whose agent is not a team member, respond in English with:",
            "'I can only answer in the following languages: English and Japanese. Please ask your question in one of these languages.'",
            "Always check the language of the user's input before routing to an agent.",
            "For unsupported languages like Italian, respond in English with the above message.",
        ],
        show_members_responses=True,
    )
    
    return multi_language_team


def main():
    """Run the language routing example."""
    print("=" * 60)
    print("Language Routing Team Example")
    print("=" * 60)
    print()
    
    team = create_language_routing_team()
    
    # Test English
    print("\n--- Testing English ---")
    team.print_response("How are you?", stream=True)
    
    # Test Japanese
    print("\n\n--- Testing Japanese ---")
    team.print_response("お元気ですか?", stream=True)
    
    # Test unsupported language (Italian)
    print("\n\n--- Testing Unsupported Language (Italian) ---")
    team.print_response("Come stai?", stream=True)
    
    print("\n\n" + "=" * 60)
    print("Language Routing Example Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
