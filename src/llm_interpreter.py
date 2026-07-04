import os
import re
import requests
import logging
import ipaddress

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
        
    prompt = f"""Bir SOC (Siber Güvenlik Operasyon Merkezi) analisti olarak aşağıdaki GÜVENLİK TEHDİDİNİ değerlendir:

TEHDİT DETAYI: {threat_message}
KAYNAK IP: {ip}
DURUM: {ip_info['isp']} ({ip_info['org']})

KURALLAR:
1. SADECE IP adresine bakarak "Güvenilir" kararı VERME! Tehdidin içeriği (Command Injection, SQLi, Keylogger) IP adresinden çok daha kritiktir.
2. 127.0.0.1 normalde yerel iletişimdir, ANCAK içerikte 'Injection', 'Payload' veya 'Keylogger' şüphesi varsa, bu bir iç ağ sızması (SSRF/Lateral Movement) girişimidir. RİSK YÜKSEKTİR!
3. Microsoft/Google IP'leri güvenilir olsa da, bu IP'lerden gelen bir 'İmza/Payload' tehdidi varsa, bu bulut servislerinin saldırı amacıyla kötüye kullanıldığını gösterir.
4. Asla laf kalabalığı yapma, doğrudan teknik aksiyon ver.

YANIT FORMATI:
- Tehdit Vektörü: [Saldırının tam olarak ne olduğu]
- Risk: [Düşük/Orta/Yüksek/Kritik] - [Kısa ve net teknik nedeni]
- Aksiyon: [Sistemi korumak için tek cümlelik öneri]"""
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,  
            "num_predict": 350
        }
    }

    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        return result.get("response", "LLM analiz döndürmedi.").strip()
        
    except Exception as e:
        logger.error(f"Ollama entegrasyon hatası: {str(e)}")
        return "Yapay zeka analiz sürecinde kritik hata."

def explain_threat(threat, all_threats_text=""):
    ip = extract_ip_from_threat(threat)
    
    if not ip:
        return "Log formatında IP bulunamadı."
        
    ip_info = get_offline_ip_info(ip)
    
    # DÜZELTME: Artık LLM'e sadece IP'yi değil, tehdidin kendisini de (threat) gönderiyoruz!
    analysis = analyze_ip_with_llm(ip, ip_info, threat)
    
    return f"{analysis}\n\n[Sistem Notu]:\n{all_threats_text[:300]}..."