"""
Julia Browser Tools for Agno Agent
Wrapper around julia_browser AgentSDK for web browsing capabilities
"""

import json
import os
from typing import Optional
from contextlib import redirect_stdout, redirect_stderr
from julia_browser import AgentSDK


class JuliaBrowserTools:
    """Julia Browser tools for web browsing, element interaction, and form submission"""
    
    def __init__(self):
        """Initialize the Julia Browser AgentSDK"""
        with open(os.devnull, 'w') as devnull:
            with redirect_stdout(devnull), redirect_stderr(devnull):
                self.browser = AgentSDK()
        self.current_url = None
    
    def open_website(self, url: str) -> str:
        """
        Open a website and return its title and basic information.
        
        Args:
            url (str): The URL to open (e.g., "https://example.com")
        
        Returns:
            str: JSON string containing the page title and URL
        """
        try:
            result = self.browser.open_website(url)
            self.current_url = url
            return json.dumps({
                "success": True,
                "url": url,
                "title": result.get('title', 'No title'),
                "message": f"Successfully opened: {result.get('title', url)}"
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to open website: {str(e)}"
            })
    
    def list_elements(self) -> str:
        """
        List all interactive elements on the current page.
        
        Returns:
            str: JSON string containing information about clickable elements, inputs, and buttons
        """
        try:
            elements = self.browser.list_elements()
            return json.dumps({
                "success": True,
                "total_clickable": elements.get('total_clickable', 0),
                "elements": elements,
                "message": f"Found {elements.get('total_clickable', 0)} interactive elements"
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to list elements: {str(e)}"
            })
    
    def type_text(self, element_id: int, text: str) -> str:
        """
        Type text into an input field.
        
        Args:
            element_id (int): The ID of the input element
            text (str): The text to type into the field
        
        Returns:
            str: JSON string confirming the action
        """
        try:
            self.browser.type_text(element_id, text)
            return json.dumps({
                "success": True,
                "message": f"Typed '{text}' into element {element_id}"
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to type text: {str(e)}"
            })
    
    def click_element(self, element_id: int) -> str:
        """
        Click a button or link on the page.
        
        Args:
            element_id (int): The ID of the element to click
        
        Returns:
            str: JSON string confirming the action
        """
        try:
            self.browser.click_element(element_id)
            return json.dumps({
                "success": True,
                "message": f"Clicked element {element_id}"
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to click element: {str(e)}"
            })
    
    def get_page_info(self) -> str:
        """
        Get current page title, URL, and full content.
        
        Returns:
            str: JSON string containing page information
        """
        try:
            page_info = self.browser.get_page_info()
            return json.dumps({
                "success": True,
                "url": page_info.get('url', self.current_url),
                "title": page_info.get('title', 'No title'),
                "content": page_info.get('content', ''),
                "message": f"Page info retrieved for: {page_info.get('title', 'Unknown')}"
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to get page info: {str(e)}"
            })
    
    def proxy_start(self) -> str:
        """
        Start the intercepting proxy (Burp Suite-like).
        All traffic from browser navigation will be captured and logged.
        
        Returns:
            str: JSON string confirming proxy started
        """
        try:
            result = self.browser.proxy_start()
            return json.dumps({
                "success": True,
                "message": "Intercepting proxy started - all HTTP traffic will be captured",
                "proxy_status": result
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to start proxy: {str(e)}"
            })
    
    def proxy_stop(self) -> str:
        """
        Stop the intercepting proxy.
        
        Returns:
            str: JSON string confirming proxy stopped
        """
        try:
            result = self.browser.proxy_stop()
            return json.dumps({
                "success": True,
                "message": "Intercepting proxy stopped",
                "proxy_status": result
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to stop proxy: {str(e)}"
            })
    
    def proxy_get_traffic(self, limit: Optional[int] = 10) -> str:
        """
        Get captured HTTP traffic logs (like Burp Suite's proxy history).
        
        Args:
            limit (int): Maximum number of traffic entries to return (default: 10)
        
        Returns:
            str: JSON string containing captured requests and responses
        """
        try:
            traffic_limit = limit if limit is not None else 10
            traffic = self.browser.proxy_get_traffic(limit=traffic_limit)
            return json.dumps({
                "success": True,
                "traffic_count": traffic.get('traffic_count', 0),
                "traffic": traffic.get('traffic', []),
                "message": f"Retrieved {traffic.get('traffic_count', 0)} HTTP requests/responses"
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to get traffic: {str(e)}"
            })
    
    def proxy_add_rule(self, rule_dict: str) -> str:
        """
        Add a rule for automatic request/response manipulation (Burp Suite-like match & replace).
        Rules use simple dictionaries - perfect for AI agents!
        
        Args:
            rule_dict (str): JSON string containing the rule configuration
        
        Rule Format Examples:
        {
            "name": "add_auth_header",
            "type": "request",
            "match": {"url_contains": "api"},
            "actions": {"set_headers": {"Authorization": "Bearer token123"}}
        }
        
        {
            "name": "remove_sensitive_data",
            "type": "response", 
            "match": {"content_type": "application/json"},
            "actions": {"find_replace": {"password": "***", "api_key": "***"}}
        }
        
        Returns:
            str: JSON string confirming rule added
        """
        try:
            rule = json.loads(rule_dict)
            result = self.browser.proxy_add_rule(rule)
            return json.dumps({
                "success": True,
                "rule_name": rule.get('name', 'unnamed'),
                "message": f"Rule '{rule.get('name')}' added - {rule.get('type')} traffic will be modified",
                "result": result
            })
        except json.JSONDecodeError as e:
            return json.dumps({
                "success": False,
                "error": "Invalid JSON in rule_dict",
                "message": f"Rule must be valid JSON: {str(e)}"
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to add rule: {str(e)}"
            })
    
    def proxy_clear_traffic(self) -> str:
        """
        Clear all captured traffic logs.
        
        Returns:
            str: JSON string confirming traffic cleared
        """
        try:
            result = self.browser.proxy_clear_traffic()
            return json.dumps({
                "success": True,
                "message": "All captured traffic logs cleared",
                "result": result
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to clear traffic: {str(e)}"
            })


def get_julia_browser_tools():
    """
    Get all julia browser tools as a list of functions for the Agent.
    
    Returns:
        list: List of tool functions
    """
    browser_tools = JuliaBrowserTools()
    
    return [
        browser_tools.open_website,
        browser_tools.list_elements,
        browser_tools.get_page_info,
        browser_tools.type_text,
        browser_tools.click_element,
        browser_tools.proxy_start,
        browser_tools.proxy_stop,
        browser_tools.proxy_get_traffic,
        browser_tools.proxy_add_rule,
        browser_tools.proxy_clear_traffic,
    ]
