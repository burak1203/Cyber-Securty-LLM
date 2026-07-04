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
    Ağ paketindeki Keylogger/Veri sızıntısı davranışlarını sezgisel (heuristic) olarak analiz eder.
    Statik port/host kontrolleri yerine payload yapısına odaklanır.
    """
    try:
        content = str(pkt.get("content", "")) if isinstance(pkt, dict) else str(getattr(pkt, "content", ""))
        content_ascii = pkt.get("content_ascii", "") if isinstance(pkt, dict) else getattr(pkt, "content_ascii", "")
        src = pkt.get("src", "") if isinstance(pkt, dict) else getattr(pkt, "src", "")
        
        payload = content + content_ascii
        if not payload:
            return False, ""

        # 1. Base64 ve JSON Gizleme (Obfuscation) Analizi
        # Düzenli ifade (regex) ile potansiyel JSON bloklarını güvenli bir şekilde çıkarıyoruz
        json_pattern = re.compile(r'\{.*?\}', re.DOTALL)
        potential_jsons = json_pattern.findall(payload)
        
        for json_str in potential_jsons:
            try:
                # String parçalamak yerine doğrudan JSON motoruna veriyoruz
                data = json.loads(json_str)
                
                # İç içe geçmiş Base64 şifreli veri var mı?
                if 'data' in data and isinstance(data['data'], str):
                    try:
                        decoded = base64.b64decode(data['data']).decode('utf-8', errors='strict')
                        inner_data = json.loads(decoded)
                        
                        # Keylogger'ların tipik 'timestamp' ve 'tuş vuruşu dizisi' formatı
                        if 'data' in inner_data and 'timestamp' in inner_data:
                            if isinstance(inner_data['data'], list):
                                logger.warning(f"🚨 Keylogger tespiti: {src} IP'sinden Base64/JSON şifreli tuş vuruşu transferi yakalandı.")
                                return True, "Şifrelenmiş tuş vuruşu (Keylogger) yapısı tespit edildi"
                    except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
                        continue # Base64 veya JSON değilse sessizce atla (False positive önleme)
            except json.JSONDecodeError:
                continue

        # 2. Sezgisel (Heuristic) Analiz: Sık ve küçük boyutlu HTTP POST istekleri
        # Keylogger'lar genellikle biriken tuşları küçük paketler halinde sık sık sunucuya yollar (Beaconing)
        if "POST" in payload and len(payload) < 250:
            small_packet_count = packet_stats['small_packets_per_src'].get(src, 0)
            # Eşik değeri B2B ortamı için ayarlandı
            if small_packet_count > 15: 
                logger.warning(f"⚠️ Anormal Aktivite: {src} adresinden düzenli veri sızdırma (Beaconing) şüphesi.")
                return True, "Sürekli küçük boyutlu veri transferi (Veri Sızıntısı/Keylogger şüphesi)"

        return False, ""

    except Exception as e:
        # Hataları "pass" ile yutmak yerine gerçek sorunu logluyoruz
        logger.error(f"Keylogger analizi sırasında ayrıştırma hatası: {str(e)}", exc_info=True)
        return False, ""

def analyze_payload_signatures(payload, src, dst):
    """
    Derin Paket İncelemesi (DPI): Tek paketlik ölümcül saldırıları tespit eder.
    B2B ortamlarında olmazsa olmaz imza tabanlı (Signature-based) analiz motorudur.
    """
    if not payload:
        return False, ""

    try:
        # Ağ trafiğindeki URL-encoded verileri çöz (%20 -> space vb.)
        decoded_payload = urllib.parse.unquote(payload)
        
        # Endüstri Standardı Saldırı İmzaları
        SIGNATURES = {
            "SQL Injection (SQLi)": r"(?i)(?:'|%27)\s*(?:OR|AND)\s*(?:'|%27|\d)|(?:\bUNION\b\s+\bSELECT\b)|(?:\bDROP\b\s+\bTABLE\b)",
            "Cross-Site Scripting (XSS)": r"(?i)(?:<script>|%3Cscript%3E)|(?:javascript:|onerror=|onload=)",
            "Path Traversal": r"(?i)(?:\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|c:\\windows\\system32)",
            "Command Injection": r"(?i)(?:/bin/bash|/bin/sh|cmd\.exe|powershell|-c\s+)"
        }

        for attack_type, pattern in SIGNATURES.items():
            if re.search(pattern, decoded_payload):
                logger.critical(f"Kritik Payload Tespiti: {attack_type} - Kaynak: {src} -> Hedef: {dst}")
                return True, attack_type
                
        return False, ""
    except Exception as e:
        logger.error(f"Payload analizi hatası: {str(e)}")
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
            
            # B2B STANDARDI: Dışarıdan gelen veriye asla güvenme. Zorunlu Type Casting.
            raw_content = pkt.get("content", "")
            ascii_content = pkt.get("content_ascii", "")
            uri = pkt.get("uri", "") # YENİ: URL içindeki GET parametrelerini çekiyoruz
            
            # YENİ: DPI taraması için tüm saldırı yüzeylerini (Body + ASCII + URL) birleştir
            full_payload = str(raw_content) + str(ascii_content) + str(uri)
            
            if protocol == "DATA-TEXT-LINES":
                continue
                
            if src: packet_stats['sources'][src] += 1
            if dst: packet_stats['destinations'][dst] += 1
            
            # 1. Deep Packet Inspection (DPI) -> Artık URI'yi de kapsayan full_payload taranıyor
            is_malicious, attack_type = analyze_payload_signatures(full_payload, src, dst)
            if is_malicious:
                msg = f"Kritik Payload İmzası: {attack_type} Şüphesi - Kaynak IP: {src}"
                threats.add(msg)

            # 2. Keylogger Kontrolü
            is_keylogger, reason = is_keylogger_behavior(pkt, packet_stats)
            if is_keylogger:
                msg = f"Keylogger/Veri Sızıntısı Şüphesi ({reason}) - Kaynak IP: {src}"
                threats.add(msg)

            # 3. Şüpheli Port Kontrolü
            is_suspicious, port_info = is_suspicious_port(pkt)
            if is_suspicious:
                msg = f"Şüpheli Port Kullanımı ({port_info}) - Kaynak IP: {src}"
                threats.add(msg)

        except Exception as e:
            logger.error(f"Paket tehdit analizi sırasında hata: {str(e)}", exc_info=True)

    # 4. Hacimsel (Volumetric) Analizler
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
            msg = f"Ağ Genelinde Dış Kaynaklı Hacimsel Anomali - Toplam {packet_stats['total_packets']} paket. Baskın Dış Kaynak: {top_ext_src}"
            threats.add(msg)
            
        elif top_int_src:
            # DÜZELTME: Artık LLM'i tetikleyecek "Tehdit" formatında değil, "BİLGİ" formatında çıkıyoruz.
            msg = f"BİLGİ: Yüksek İç Ağ Trafiği Olağan Hacmi - Baskın İç Kaynak: {top_int_src} ({internal_sources[top_int_src]} paket)"
            threats.add(msg)

    for src, count in external_sources.items():
        if count > DDOS_THRESHOLDS['packets_per_source']:
            msg = f"Tekil Dış Kaynaktan Yüksek İstek (Flood Şüphesi) - Kaynak IP: {src} ({count} paket)"
            threats.add(msg)

    return list(threats)