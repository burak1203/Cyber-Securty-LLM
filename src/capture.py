import pyshark
import logging
import queue
import asyncio

logger = logging.getLogger(__name__)

def packet_producer(interface, packet_queue: queue.Queue, stop_flag=None):
    # Her thread kendi izole event loop'una sahip olmalı
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    logger.info(f"📡 {interface} arayüzünden veri toplanıyor...")
    capture = None
    
    try:
        bpf_rule = "not port 5000 and not port 11434"
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_rule)
        
        for pkt in capture.sniff_continuously():
            if stop_flag is not None and stop_flag():
                logger.info("⏹️ Durdurma sinyali alındı. Tshark kapatılıyor...")
                break
            
            try:
                packet_queue.put(pkt, timeout=0.1)
            except queue.Full:
                pass
                
    except Exception as e:
        logger.error(f"Paket yakalama sırasında kritik hata: {str(e)}", exc_info=True)
    finally:
        if capture:
            try:
                capture.close()  # ÖLÜMCÜL HATA BURADAYDI. Tshark'ı zorla kapatır.
            except Exception:
                pass
        loop.close()
        logger.info("Trafik yakalama thread'i temiz bir şekilde sonlandı.")