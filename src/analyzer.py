# src/analyzer.py
import binascii
import logging

logger = logging.getLogger(__name__)

def analyze_packet_batch(packet_batch):
    """
    Kuyruktan alınan paket yığınını (batch) analiz eder.
    Senkron döngü darboğazını önlemek için tasarlandı.
    """
    if not packet_batch:
        return []

    analysis = []
    
    for pkt in packet_batch:
        try:
            src = getattr(pkt.ip, 'src', '127.0.0.1') if hasattr(pkt, 'ip') else '127.0.0.1'
            dst = getattr(pkt.ip, 'dst', '127.0.0.1') if hasattr(pkt, 'ip') else '127.0.0.1'
            protocol = pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'Unknown'
            length = int(getattr(pkt, 'length', 0)) if hasattr(pkt, 'length') else 0
            
            packet_data = {
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "length": length,
                "content": ""
            }

            content = ''
            if hasattr(pkt, 'http'):
                packet_data["method"] = getattr(pkt.http, 'request_method', '')
                packet_data["host"] = getattr(pkt.http, 'host', '')
                packet_data["uri"] = getattr(pkt.http, 'request_uri', '')
                for attr in ['file_data', 'request', 'payload', 'data', 'json_value']:
                    val = getattr(pkt.http, attr, None)
                    if val:
                        content += str(val)
            elif hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload'):
                content = getattr(pkt.tcp, 'payload', '')
            elif hasattr(pkt, 'data'):
                content = getattr(pkt, 'data', '')
                
            packet_data["content"] = content

            # Sessiz hata yutucu (pass) kaldırıldı.
            # Hex string doğrulaması eklendi.
            if isinstance(content, str) and len(content.replace(':', '')) > 20:
                hex_str = content.replace(':', '').replace(' ', '')
                # Basit bir hex karakter kontrolü
                if all(c in '0123456789abcdefABCDEF' for c in hex_str):
                    try:
                        ascii_str = binascii.unhexlify(hex_str).decode(errors='ignore')
                        packet_data['content_ascii'] = ascii_str
                    except binascii.Error as e:
                        logger.debug(f"Hex çözümleme atlandı (Geçersiz format): {e}")

            analysis.append(packet_data)

        except AttributeError as ae:
            logger.error(f"Paket özniteliği okunamadı: {ae}", exc_info=True)
        except Exception as e:
            logger.error(f"Paket analizi sırasında beklenmeyen hata: {e}", exc_info=True)

    return analysis