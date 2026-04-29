# Python 3.11 slim — küçük image, hızlı pull
FROM python:3.11-slim

# Çalışma dizini
WORKDIR /app

# Sistem paketleri (gcc bazı paketlerin C uzantıları için lazım olabilir)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Önce sadece requirements'ı kopyala — Docker layer cache için
# requirements değişmediği sürece pip install adımı yeniden çalışmaz
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Uygulama kodunu kopyala
COPY app/ ./app/
COPY data/ ./data/

# DB dosyaları için klasör (volume mount edilecek)
RUN mkdir -p /app/data

# FastAPI portu
EXPOSE 8000

# Production'da --reload yok
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]