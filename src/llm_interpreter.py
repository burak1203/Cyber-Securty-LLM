import os
import re
import requests
import logging
import ipaddress
from pydantic import ValidationError
from src.schemas import ThreatAnalysisResponse

logger = logging.getLogger(__name__)

# Ollama yapılandırması
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral") 

def is_private_ip(ip_str):
    """IP'nin yerel ağda olup olmadığını kontrol eder."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

def extract_ip_from_threat(threat_msg):
    """Tehdit logundan IPv4 adresini güvenli bir şekilde çeker."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, threat_msg)
    return match.group(0) if match else None

def get_offline_ip_info(ip):
    """
    DİKKAT: ipinfo.io gibi dış servislere veri sızdırmamak için çevrimdışı çalışır.
    TODO: B2B sürümünde buraya MaxMind GeoLite2 Offline veritabanı entegre edilecek.
    """
    if not ip:
        return None
        
    info = {"ip": ip, "isp": "Bilinmiyor", "org": "Bilinmiyor", "country": "Bilinmiyor", "city": "Bilinmiyor", "as": "Bilinmiyor"}
    
    if is_private_ip(ip):
        info["isp"] = "Yerel Ağ (LAN)"
        info["org"] = "Internal Network"
    else:
        info["isp"] = "Dış Ağ (Public)"
        info["org"] = "External Entity"
        
    return info

def analyze_ip_with_llm(ip, ip_info, threat_message):
    if not ip_info:
        return "IP analiz verisi oluşturulamadı."
        
    # İstem (Prompt) artık destan istemiyor, kesin bir JSON bekliyor
    prompt = f"""Bir SOC analisti olarak aşağıdaki GÜVENLİK TEHDİDİNİ değerlendir.
TEHDİT DETAYI: {threat_message}
KAYNAK IP: {ip}
DURUM: {ip_info['isp']} ({ip_info['org']})

SADECE VE SADECE aşağıdaki JSON formatında, geçerli bir JSON objesi dön. Ekstra hiçbir metin, selamlama veya açıklama ekleme:
{{
    "threat_vector": "Tehdidin teknik adı",
    "risk_level": "Düşük, Orta, Yüksek veya Kritik",
    "action_required": "Alınacak tek cümlelik acil aksiyon"
}}"""
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "format": "json", # Ollama'yı katı JSON moduna zorlar
        "stream": False,
        "options": {
            "temperature": 0.0,  # Halüsinasyonu sıfıra indirmek için 0.0
            "num_predict": 250
        }
    }

    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        raw_llm_response = result.get("response", "{}").strip()
        
        # Pydantic ile Veri Sözleşmesini (Data Contract) Doğrulama
        try:
            validated_data = ThreatAnalysisResponse.model_validate_json(raw_llm_response)
            
            # Sistemden geçen, doğrulanmış temiz veri
            return (
                f"[DOĞRULANMIŞ ANALİZ]\n"
                f"- Tehdit Vektörü: {validated_data.threat_vector}\n"
                f"- Risk Seviyesi: {validated_data.risk_level}\n"
                f"- Acil Aksiyon: {validated_data.action_required}"
            )
        except ValidationError as ve:
            # LLM kurallara uymazsa sistem çökmez, güvenlik kalkanı (guardrail) devreye girer
            logger.error(f"LLM Veri Sözleşmesini İhlal Etti: {str(ve)}\nHam Yanıt: {raw_llm_response}")
            return "SİSTEM UYARISI: LLM, yapısal veri sözleşmesini ihlal eden bir yanıt ürettiği için analiz reddedildi."
            
    except Exception as e:
        logger.error(f"Ollama entegrasyon hatası: {str(e)}")
        return "Yapay zeka analiz sürecinde kritik API hatası."

def explain_threat(threat, all_threats_text=""):
    ip = extract_ip_from_threat(threat)
    
    if not ip:
        return "Log formatında IP bulunamadı."
        
    ip_info = get_offline_ip_info(ip)
    
    # DÜZELTME: Artık LLM'e sadece IP'yi değil, tehdidin kendisini de (threat) gönderiyoruz!
    analysis = analyze_ip_with_llm(ip, ip_info, threat)
    
    return f"{analysis}\n\n[Sistem Notu]:\n{all_threats_text[:300]}..."