import re
import json
import base64
import logging
import ipaddress
import urllib.parse
from collections import defaultdict
from src.utils import summarize_packet, is_suspicious_port, is_normal_traffic, write_to_log

logger = logging.getLogger(__name__)

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def is_keylogger_behavior(pkt, packet_stats):
    """
    Heuristically analyzes network packets for Keylogger/Data Leakage behaviors.
    Focuses on payload structure rather than static port/host checks.
    """
    try:
        content = str(pkt.get("content", "")) if isinstance(pkt, dict) else str(getattr(pkt, "content", ""))
        content_ascii = pkt.get("content_ascii", "") if isinstance(pkt, dict) else getattr(pkt, "content_ascii", "")
        src = pkt.get("src", "") if isinstance(pkt, dict) else getattr(pkt, "src", "")
        
        payload = content + content_ascii
        if not payload:
            return False, ""

        # 1. Base64 and JSON Obfuscation Analysis
        # Safely extract potential JSON blocks using regular expressions
        json_pattern = re.compile(r'\{.*?\}', re.DOTALL)
        potential_jsons = json_pattern.findall(payload)
        
        for json_str in potential_jsons:
            try:
                # Feed directly to the JSON engine instead of string parsing
                data = json.loads(json_str)
                
                # Check for nested Base64 encoded data
                if 'data' in data and isinstance(data['data'], str):
                    try:
                        decoded = base64.b64decode(data['data']).decode('utf-8', errors='strict')
                        inner_data = json.loads(decoded)
                        
                        # Typical 'timestamp' and 'keystroke array' format of keyloggers
                        if 'data' in inner_data and 'timestamp' in inner_data:
                            if isinstance(inner_data['data'], list):
                                logger.warning(f"🚨 Keylogger detection: Base64/JSON encrypted keystroke transfer caught from IP {src}.")
                                return True, "Encrypted keystroke (Keylogger) structure detected"
                    except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
                        continue # Skip silently if not Base64 or JSON (Prevents false positives)
            except json.JSONDecodeError:
                continue

        # 2. Heuristic Analysis: Frequent and small HTTP POST requests
        # Keyloggers typically beacon accumulated keystrokes to the server in small packets
        if "POST" in payload and len(payload) < 250:
            small_packet_count = packet_stats['small_packets_per_src'].get(src, 0)
            # Threshold tuned for B2B environments
            if small_packet_count > 15: 
                logger.warning(f"⚠️ Anomalous Activity: Suspected continuous data beaconing from {src}.")
                return True, "Continuous small-scale data transfer (Suspected Data Leakage/Keylogger)"

        return False, ""

    except Exception as e:
        # Logging the actual issue instead of swallowing errors with "pass"
        logger.error(f"Parsing error during keylogger analysis: {str(e)}", exc_info=True)
        return False, ""

def analyze_payload_signatures(payload, src, dst):
    """
    Deep Packet Inspection (DPI): Detects single-packet lethal attacks.
    Essential signature-based analysis engine for B2B environments.
    """
    if not payload:
        return False, ""

    try:
        # Decode URL-encoded data in network traffic (%20 -> space, etc.)
        decoded_payload = urllib.parse.unquote(payload)
        
        # Industry Standard Attack Signatures
        SIGNATURES = {
            "SQL Injection (SQLi)": r"(?i)(?:'|%27)\s*(?:OR|AND)\s*(?:'|%27|\d)|(?:\bUNION\b\s+\bSELECT\b)|(?:\bDROP\b\s+\bTABLE\b)",
            "Cross-Site Scripting (XSS)": r"(?i)(?:<script>|%3Cscript%3E)|(?:javascript:|onerror=|onload=)",
            "Path Traversal": r"(?i)(?:\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|c:\\windows\\system32)",
            "Command Injection": r"(?i)(?:/bin/bash|/bin/sh|cmd\.exe|powershell|-c\s+)"
        }

        for attack_type, pattern in SIGNATURES.items():
            if re.search(pattern, decoded_payload):
                logger.critical(f"Critical Payload Detection: {attack_type} - Source: {src} -> Destination: {dst}")
                return True, attack_type
                
        return False, ""
    except Exception as e:
        logger.error(f"Payload analysis error: {str(e)}")
        return False, ""


def detect_threats(packets, stop_flag=None):
    threats = set()
    packet_stats = {
        'total_packets': len(packets),
        'protocols': defaultdict(int),
        'sources': defaultdict(int),
        'destinations': defaultdict(int),
        'large_packets': 0,
        'small_packets': 0,
        'small_packets_per_src': defaultdict(int)
    }

    DDOS_THRESHOLDS = {'packets_per_source': 500, 'total_packets': 5000}

    for pkt in packets:
        if stop_flag is not None and stop_flag():
            break
            
        try:
            protocol = pkt.get("protocol", "")
            src = pkt.get("src", "")
            dst = pkt.get("dst", "")
            length = int(pkt.get("length", 0))
            
            # B2B STANDARD: Never trust external data. Mandatory Type Casting.
            raw_content = pkt.get("content", "")
            ascii_content = pkt.get("content_ascii", "")
            uri = pkt.get("uri", "") # NEW: Extracting GET parameters from the URL
            
            # NEW: Combine all attack surfaces (Body + ASCII + URL) for DPI scanning
            full_payload = str(raw_content) + str(ascii_content) + str(uri)
            
            if protocol == "DATA-TEXT-LINES":
                continue
                
            if src: packet_stats['sources'][src] += 1
            if dst: packet_stats['destinations'][dst] += 1
            
            # 1. Deep Packet Inspection (DPI) -> Full payload including URI is now scanned
            is_malicious, attack_type = analyze_payload_signatures(full_payload, src, dst)
            if is_malicious:
                msg = f"Critical Payload Signature: Suspected {attack_type} - Source IP: {src}"
                threats.add(msg)

            # 2. Keylogger Check
            is_keylogger, reason = is_keylogger_behavior(pkt, packet_stats)
            if is_keylogger:
                msg = f"Suspected Keylogger/Data Leakage ({reason}) - Source IP: {src}"
                threats.add(msg)

            # 3. Suspicious Port Check
            is_suspicious, port_info = is_suspicious_port(pkt)
            if is_suspicious:
                msg = f"Suspicious Port Usage ({port_info}) - Source IP: {src}"
                threats.add(msg)

        except Exception as e:
            logger.error(f"Error during packet threat analysis: {str(e)}", exc_info=True)

    # 4. Volumetric Analysis
    LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost"}
    external_sources = {}
    internal_sources = {}
    
    for ip, count in packet_stats['sources'].items():
        if ip in LOOPBACK_IPS:
            continue
        if is_private_ip(ip):
            internal_sources[ip] = count
        else:
            external_sources[ip] = count

    if packet_stats['total_packets'] > DDOS_THRESHOLDS['total_packets']:
        top_ext_src = max(external_sources, key=external_sources.get) if external_sources else None
        top_int_src = max(internal_sources, key=internal_sources.get) if internal_sources else None
        
        if top_ext_src and external_sources[top_ext_src] > DDOS_THRESHOLDS['packets_per_source']:
            msg = f"Network-Wide External Volumetric Anomaly - Total {packet_stats['total_packets']} packets. Dominant External Source: {top_ext_src}"
            threats.add(msg)
            
        elif top_int_src:
            # FIX: Outputting in "INFO" format instead of "Threat" to avoid triggering the LLM.
            msg = f"INFO: High Internal Network Traffic Volume - Dominant Internal Source: {top_int_src} ({internal_sources[top_int_src]} packets)"
            threats.add(msg)

    for src, count in external_sources.items():
        if count > DDOS_THRESHOLDS['packets_per_source']:
            msg = f"High Request Volume from Single External Source (Suspected Flood) - Source IP: {src} ({count} packets)"
            threats.add(msg)

    return list(threats)