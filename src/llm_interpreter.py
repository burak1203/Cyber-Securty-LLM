import os
import re
import requests
import logging
import ipaddress
from pydantic import ValidationError
from src.schemas import ThreatAnalysisResponse

logger = logging.getLogger(__name__)

# Ollama configuration
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral") 

def is_private_ip(ip_str):
    """Checks if the IP belongs to a local network."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

def extract_ip_from_threat(threat_msg):
    """Safely extracts the IPv4 address from the threat log."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, threat_msg)
    return match.group(0) if match else None

def get_offline_ip_info(ip):
    """
    WARNING: Operates offline to prevent data leakage to external services like ipinfo.io.
    TODO: Integrate MaxMind GeoLite2 Offline database here for the B2B release.
    """
    if not ip:
        return None
        
    info = {"ip": ip, "isp": "Unknown", "org": "Unknown", "country": "Unknown", "city": "Unknown", "as": "Unknown"}
    
    if is_private_ip(ip):
        info["isp"] = "Local Network (LAN)"
        info["org"] = "Internal Network"
    else:
        info["isp"] = "External Network (Public)"
        info["org"] = "External Entity"
        
    return info

def analyze_ip_with_llm(ip, ip_info, threat_message):
    if not ip_info:
        return "Failed to generate IP analysis data."
        
    # Prompt now requires strict JSON output instead of verbose text
    prompt = f"""Evaluate the following SECURITY THREAT as a SOC analyst.
THREAT DETAIL: {threat_message}
SOURCE IP: {ip}
STATUS: {ip_info['isp']} ({ip_info['org']})

Return a valid JSON object EXACTLY in the following format. Do not add any extra text, greetings, or explanations:
{{
    "threat_vector": "Technical name of the threat",
    "risk_level": "Low, Medium, High, or Critical",
    "action_required": "A single-sentence immediate action to be taken"
}}"""
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "format": "json", # Forces Ollama into strict JSON mode
        "stream": False,
        "options": {
            "temperature": 0.0,  # Set to 0.0 to eliminate hallucination
            "num_predict": 250
        }
    }

    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        raw_llm_response = result.get("response", "{}").strip()
        
        # Validate Data Contract via Pydantic
        try:
            validated_data = ThreatAnalysisResponse.model_validate_json(raw_llm_response)
            
            # Validated clean data passed through the system
            return (
                f"[VALIDATED ANALYSIS]\n"
                f"- Threat Vector: {validated_data.threat_vector}\n"
                f"- Risk Level: {validated_data.risk_level}\n"
                f"- Immediate Action: {validated_data.action_required}"
            )
        except ValidationError as ve:
            # System does not crash if LLM violates rules; guardrails engage
            logger.error(f"LLM Data Contract Violation: {str(ve)}\nRaw Response: {raw_llm_response}")
            return "SYSTEM WARNING: Analysis rejected due to LLM violating the structural data contract."
            
    except Exception as e:
        logger.error(f"Ollama integration error: {str(e)}")
        return "Critical API error during AI analysis process."

def explain_threat(threat, all_threats_text=""):
    ip = extract_ip_from_threat(threat)
    
    if not ip:
        return "No IP found in log format."
        
    ip_info = get_offline_ip_info(ip)
    
    # FIX: Forwarding both the threat details and the IP to the LLM
    analysis = analyze_ip_with_llm(ip, ip_info, threat)
    
    return f"{analysis}\n\n[System Note]:\n{all_threats_text[:300]}..."