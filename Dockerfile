FROM python:3.10.6-slim

# Tshark kurulumu
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Konteyner çalışma dizini
WORKDIR /app

# Sadece temizlenmiş hayati paketleri kopyala ve kur
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kodun tamamını içeri al
COPY . .

# Flask portu
EXPOSE 5000

# Sistemi başlat
CMD ["python", "app.py"]