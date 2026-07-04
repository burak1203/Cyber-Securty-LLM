# CyberSec-LLM: Enterprise Network Threat Analyzer

CyberSec-LLM, kurumsal ağ trafiklerini gerçek zamanlı olarak izleyen, Derin Paket İncelemesi (DPI) yapan ve tespit edilen tehditleri yerel Yapay Zeka (Local LLM) ile tamamen izole bir şekilde analiz eden bir Güvenlik Operasyon Merkezi (SOC) aracıdır.

Bu araç, B2B gizlilik standartlarına (Zero-Data-Leak) uygun olarak tasarlanmıştır. Mahrem ağ loglarınız hiçbir şekilde dışarıdaki 3. parti bulut servislerine (OpenAI, HuggingFace vb.) sızdırılmaz; tüm yapay zeka analizleri on-premise (yerel) sunucularınızda çalışır.

## 🚀 Kurumsal Özellikler (Enterprise Features)

- **Tam İzolasyon (Local LLM):** Ollama entegrasyonu ile analizler yerel makinede yapılır. Ağ verisi şirket dışına çıkmaz.
- **Derin Paket İnceleme (DPI):** SQL Injection, Cross-Site Scripting (XSS), Command Injection ve Path Traversal saldırılarını paket gövdesinden havada yakalayan imza tabanlı tespit motoru.
- **Asenkron Kuyruk Mimarisi (Zero Bottleneck):** Producer-Consumer mimarisi ile Gigabit seviyesindeki ağ trafiğinde bile I/O ve işlemci darboğazı yaşatmayan thread-safe paket işleme.
- **Akıllı Hacimsel Analiz:** İç ağ olağan trafiği (Loopback/Private IP) ile dış kaynaklı gerçek DDoS/Flood saldırılarını birbirinden ayırt eden hacimsel filtreleme.
- **Konteyner Mimari (Dockerized):** İşletim sisteminden bağımsız, tek satır komutla ayağa kalkan izole ve kararlı çalışma ortamı.

## 🛠️ Sistem Gereksinimleri

- Docker ve Docker Compose
- Ollama (Yerel LLM sunucusu için)
- En az 8GB RAM (Mistral/Llama3 modelinin rahat çalışabilmesi için)

## 📦 Kurulum ve Dağıtım (Deployment)

Proje, herhangi bir Python bağımlılığı veya Tshark kurulumu gerektirmeden doğrudan Docker üzerinden ayağa kalkacak şekilde yapılandırılmıştır.

1. **Yerel LLM Sunucusunu Hazırlayın:**
   Sunucunuza [Ollama](https://ollama.com/)'yı kurun ve analiz modelini indirin:
   ```bash
   ollama run mistral
   ```

2. **Depoyu Klonlayın:**
   ```bash
   git clone [https://github.com/burak1203/cyber-securty-llm.git](https://github.com/burak1203/cyber-securty-llm.git)
   cd cyber-securty-llm
   ```

3. **Docker ile Sistemi Ayağa Kaldırın:**
   ```bash
   docker-compose build --no-cache
   docker-compose up -d
   ```

4. **Panele Erişim:**
   Tarayıcınızdan `http://localhost:5000` adresine giderek analiz paneline ulaşabilirsiniz.

## 🛡️ Güvenlik ve Mimari Notları

- Uygulama, Docker üzerinde `network_mode: "host"` (veya port binding) ile çalışır ve `NET_ADMIN` / `NET_RAW` yetkilerini kullanarak çekirdek (kernel) seviyesinde ağ kartını dinler.
- Gürültüyü engellemek ve "Alert Fatigue" (Uyarı Yorgunluğu) yaratmamak adına, iç ağdaki rutin yüksek veri transferleri LLM motorunu meşgul etmez, sadece bilgi logu olarak işlenir.

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.