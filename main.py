import queue
import threading
import time
import traceback
import logging
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from src.capture import packet_producer
from src.analyzer import analyze_packet_batch
from src.detector import detect_threats
from src.llm_interpreter import explain_threat
from src.utils import log_time, write_to_log, group_threats

def log_and_print(msg, filename="network_analysis.log"):
    write_to_log(msg, filename=filename)
    print(msg)

def ensure_log_files():
    """Reset log files at the beginning of a new analysis session."""
    log_files = ["network_analysis.log", "llm_analysis.log"]
    for file in log_files:
        with open(file, "w", encoding="utf-8") as f:
            f.write("")

def run_full_analysis(stop_flag=None):
    try:
        ensure_log_files()
        
        with open("network_analysis.log", "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n[{log_time()}] Real-Time SOC Analysis Initiated\n{'='*80}\n")
        with open("llm_analysis.log", "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n[{log_time()}] LLM Threat Analysis Log\n{'='*80}\n")

        log_and_print(f"\n[{log_time()}] Listening on network interface. Queue architecture active...")

        # Initialize thread-safe queue with backpressure limits
        packet_queue = queue.Queue(maxsize=5000)
        
        # Configure the target network interface (e.g., 'eth0', 'any', 'Ethernet')
        interface = "any"  
        
        capture_thread = threading.Thread(
            target=packet_producer,
            args=(interface, packet_queue, stop_flag),
            daemon=True
        )
        capture_thread.start()

        all_threats = set()
        all_analyzed_results = []
        
        log_and_print(f"\n[{log_time()}] Consumer thread processing packet batches...")

        batch_size = 100
        
        while stop_flag is not None and not stop_flag():
            batch = []
            try:
                for _ in range(batch_size):
                    try:
                        # Prevent blocking if the queue is empty
                        pkt = packet_queue.get(timeout=0.1)
                        batch.append(pkt)
                    except queue.Empty:
                        break
                
                if batch:
                    results = analyze_packet_batch(batch)
                    all_analyzed_results.extend(results)
                    
                    batch_threats = detect_threats(results, lambda: False)
                    for threat in batch_threats:
                        if threat not in all_threats:
                            log_and_print(f"[LIVE THREAT] {threat}")
                            all_threats.add(threat)
                else:
                    time.sleep(0.1)
                    
            except KeyboardInterrupt:
                log_and_print("\n[!] Process interrupted. Transitioning to LLM analysis phase...")
                break

        log_and_print(f"\n[{log_time()}] Stop signal received. Flushing remaining packets...")
        capture_thread.join(timeout=2)

        log_and_print(f"\n[{log_time()}] Executing final volumetric threat analysis...")
        final_threats = detect_threats(all_analyzed_results, lambda: False)
        for t in final_threats:
            if t not in all_threats:
                log_and_print(f"[VOLUMETRIC THREAT] {t}")
                all_threats.add(t)

        if not all_threats:
            msg = "System Secure: No suspicious network activity detected."
            log_and_print(f"\n[{log_time()}] {msg}")
            return msg

        log_and_print(f"\n[{log_time()}] Generating LLM insights for detected anomalies...\n")
        
        grouped_threats = group_threats(list(all_threats))
        all_threats_text = ""
        for threat_type, threat_list in grouped_threats.items():
            all_threats_text += f"\n{threat_type} Threats:\n" + "-" * 50 + "\n"
            for threat in threat_list:
                all_threats_text += f"{threat}\n"
        
        # FIXED: Category strings now perfectly match the output of group_threats() in utils.py
        priority_threats = [
            "Critical Payload (DPI)", 
            "Volumetric Anomaly", 
            "Data Leakage / Keylogger", 
            "Suspicious Port", 
            "General Traffic Anomaly"
        ]
        
        result_text = ""
        
        for threat_type in priority_threats:
            if threat_type in grouped_threats:
                threat_list = grouped_threats[threat_type]
                log_and_print(f"\n{threat_type}:")
                log_and_print("-" * 50)
                for threat in threat_list:
                    log_and_print(f"{threat}")
                
                if threat_list:
                    try:
                        example_threat = threat_list[0]
                        explanation = explain_threat(example_threat, all_threats_text)
                        log_and_print(f"\nAnalysis:\n{explanation}", filename="llm_analysis.log")
                        result_text += f"\n[{threat_type}]\n{explanation}\n"
                    except Exception as e:
                        log_and_print(f"\n[ERROR] LLM analysis failed: {str(e)}", filename="llm_analysis.log")
                log_and_print("-" * 50)

        log_and_print(f"\n[{log_time()}] SOC Analysis Completed.\n{'='*80}")
        return result_text if result_text else "Threats detected, but LLM analysis yielded no results."

    except Exception as e:
        error_msg = f"\n[{log_time()}] [CRITICAL ERROR] Execution failed:\n{str(e)}\n{traceback.format_exc()}"
        log_and_print(error_msg)
        log_and_print(error_msg, filename="llm_analysis.log")
        return error_msg