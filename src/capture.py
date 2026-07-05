import pyshark
import logging
import queue
import asyncio

logger = logging.getLogger(__name__)

def packet_producer(interface, packet_queue: queue.Queue, stop_flag=None):
    # Each thread must have its isolated event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    logger.info(f"📡 Collecting data from interface {interface}...")
    capture = None
    
    try:
        bpf_rule = "not port 5000 and not port 11434"
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_rule)
        
        for pkt in capture.sniff_continuously():
            if stop_flag is not None and stop_flag():
                logger.info("⏹️ Stop signal received. Closing Tshark...")
                break
            
            try:
                packet_queue.put(pkt, timeout=0.1)
            except queue.Full:
                pass
                
    except Exception as e:
        logger.error(f"Critical error during packet capture: {str(e)}", exc_info=True)
    finally:
        if capture:
            try:
                capture.close()  # FATAL ERROR WAS HERE. Forcefully closes Tshark.
            except Exception:
                pass
        loop.close()
        logger.info("Traffic capture thread terminated cleanly.")