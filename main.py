# -*- coding: utf-8 -*-
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
    """Her analiz başlangıcında log dosyalarını oluşturur ve içlerini sıfırlar."""
    log_files = ["network_analysis.log", "llm_analysis.log"]
    for file in log_files:
        with open(file, "w", encoding="utf-8") as f:
            f.write("") # Dosyayı tamamen boşaltarak sıfırdan başlatır

def run_full_analysis(stop_flag=None):
    try:
        ensure_log_files() # Önce dosyaları temizle
        
        with open("network_analysis.log", "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n[{log_time()}] Gerçek Zamanlı Analiz Başlatıldı\n{'='*80}\n")
        with open("llm_analysis.log", "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n[{log_time()}] LLM Analiz Logu\n{'='*80}\n")

        log_and_print(f"\n[{log_time()}] Ağ arayüzü dinleniyor, kuyruk mimarisi devrede...")

        packet_queue = queue.Queue(maxsize=5000)

        # Ağ arayüzünü kendi ortamına göre değiştir (Örn: Ethernet veya Wi-Fi)
        interface = "any"  
        
        capture_thread = threading.Thread(
            target=packet_producer,
            args=(interface, packet_queue, stop_flag),
            daemon=True
        )
        capture_thread.start()

        all_threats = set()
        all_analyzed_results = []
        
        log_and_print(f"\n[{log_time()}] Paketler kuyruktan çekilip gerçek zamanlı işleniyor...")

        batch_size = 100
        
        while stop_flag is not None and not stop_flag():
            batch = []
            try:
                for _ in range(batch_size):
                    try:
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
                            log_and_print(f"YENİ ANLIK TEHDİT: {threat}")
                            all_threats.add(threat)
                else:
                    time.sleep(0.1)
                    
            except KeyboardInterrupt:
                log_and_print("\n[!] CTRL+C algılandı. Dinleme döngüsü kırılıyor, Ollama analiz aşamasına geçiliyor...")
                break

        log_and_print(f"\n[{log_time()}] Durdurma sinyali işlendi. Kuyruktaki son paketler temizleniyor...")
        capture_thread.join(timeout=2)

        log_and_print(f"\n[{log_time()}] Toplam trafik üzerinden son hacimsel tehdit analizi yapılıyor...")
        final_threats = detect_threats(all_analyzed_results, lambda: False)
        for t in final_threats:
            if t not in all_threats:
                log_and_print(f"HACİMSEL TEHDİT: {t}")
                all_threats.add(t)

        if not all_threats:
            msg = "Her şey yolunda! Şüpheli bir aktivite tespit edilmedi."
            log_and_print(f"\n[{log_time()}] {msg}")
            return msg

        log_and_print(f"\n[{log_time()}] LLM ile açıklamalar hazırlanıyor...\n")
        
        grouped_threats = group_threats(list(all_threats))
        all_threats_text = ""
        for threat_type, threat_list in grouped_threats.items():
            all_threats_text += f"\n{threat_type} Tehditleri:\n" + "-" * 50 + "\n"
            for threat in threat_list:
                all_threats_text += f"{threat}\n"
        
        # Güncel Kategori İsimleri
        priority_threats = ["Kritik Payload (DPI)", "Hacimsel Anomali", "Veri Sızıntısı / Keylogger", "Şüpheli Port", "Genel Trafik Anomalisi"]
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
                        log_and_print(f"\nAnaliz:\n{explanation}", filename="llm_analysis.log")
                        result_text += f"\n[{threat_type}]\n{explanation}\n"
                    except Exception as e:
                        log_and_print(f"\nLLM analizi yapılamadı: {str(e)}", filename="llm_analysis.log")
                        log_and_print("Analiz atlanıyor ve devam ediliyor...", filename="llm_analysis.log")
                log_and_print("-" * 50)

        log_and_print(f"\n[{log_time()}] Analiz tamamlandı.\n{'='*80}")
        return result_text if result_text else "Tehditler tespit edildi, ancak analiz sonucu yok."

    except Exception as e:
        error_msg = f"\n[{log_time()}] Hata oluştu:\n{str(e)}\n{traceback.format_exc()}"
        log_and_print(error_msg)
        log_and_print(error_msg, filename="llm_analysis.log")
        return error_msg

def main():
    print("Test amacıyla çalıştırılıyor. Durdurmak ve LLM Analizini tetiklemek için CTRL+C yapın.")
    run_full_analysis(lambda: False)

if __name__ == "__main__":
    main()