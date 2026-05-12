# CloudGuard AI

> Cloud Security Monitoring & Incident Response Agent — AWS bulut altyapılarındaki güvenlik loglarını analiz eden, tehditleri tespit eden ve müdahale önerileri sunan yapay zeka destekli bir SOC asistanı.

CloudGuard AI, doğal dilde sorulan güvenlik sorularına cevap verirken arka planda **7 farklı güvenlik aracını** (CloudTrail / VPC Flow / Auth log analizi, AWS yapılandırma denetimi, IP itibar sorgusu, alert kaydı, müdahale playbook'u) kullanan bir LangGraph ReAct agent'ıdır. Bulguları MITRE ATT&CK çerçevesine göre sınıflandırır, kalıcı bellekle önceki konuşmaları hatırlar ve gerçek zamanlı bir dashboard üzerinde sonuçları görselleştirir.

---

## İçindekiler

- [Demo](#demo)
- [Özellikler](#özellikler)
- [Mimari](#mimari)
- [Tech Stack](#tech-stack)
- [Hızlı Başlangıç](#hızlı-başlangıç)
- [Geliştirme](#geliştirme)
- [Güvenlik Araçları](#güvenlik-araçları)
- [API Endpoint'leri](#api-endpointleri)
- [Test ve CI](#test-ve-ci)
- [Dosya Yapısı](#dosya-yapısı)
- [Geliştiriciler](#geliştiriciler)

---

## Demo

Doğal dilde bir güvenlik sorusu sorduğunuzda agent uygun tool'u seçer, gerekirse birden fazla tool'u zincirleme çağırır ve bulguları severity + MITRE ATT&CK metadata ile döndürür.

**Örnek senaryo:**

> Kullanıcı: *"Son CloudTrail loglarında şüpheli aktivite var mı? Bulguları alert olarak kaydet."*
>
> Agent şunları yapar:
> 1. `analyze_cloudtrail_logs` çağrılır → 14 bulgu
> 2. Bulgularda IP'ler için `check_ip_reputation` (otomatik enrichment)
> 3. CRITICAL/HIGH bulgular için `generate_alert` × N → DB'ye kaydet
> 4. Türkçe özet + öneri üretir

Sonuçlar dashboard'a anlık olarak yansır: severity dağılımı donut chart'ı, alert listesi, tool kullanım feed'i.

---

## Özellikler

- **🤖 LangGraph ReAct Agent** — Gemini 2.5 Flash ile çok adımlı reasoning
- **🛡️ 7 Güvenlik Aracı** — Log analizi, config audit, threat intel, alert kaydı, remediation playbook
- **💾 Kalıcı Bellek** — SQLite checkpointer ile thread bazlı konuşma geçmişi
- **🎯 MITRE ATT&CK Mapping** — Her bulgu için tactic + technique referansı
- **📊 Live Dashboard** — Severity grafiği, alert paneli, tool aktivite feed'i
- **🔌 Tool Görünürlüğü** — Mesaj baloncuklarında çağrılan tool'ların rozetleri
- **🌍 Türkçe Doğal Dil** — Soru ve cevap tamamen Türkçe
- **🐳 Docker Compose** — Tek komutla full stack deploy
- **✅ CI/CD** — Her PR'da ruff lint + pytest

---

## Mimari

```
┌─────────────────────────────────────────────────────────┐
│                      FRONTEND                           │
│  React + Tailwind v4                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Chat Arayüzü │  │  Dashboard   │  │ Alert Panel  │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└──────────────────────┬──────────────────────────────────┘
                       │ /api/* (Vite proxy → :8000)
┌──────────────────────▼──────────────────────────────────┐
│                      BACKEND                            │
│  FastAPI + Uvicorn                                      │
│  ┌──────────────────────────────────────────────────┐   │
│  │           LangGraph ReAct Agent                  │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │   │
│  │  │  LLM     │ │  Memory  │ │  Tool Executor   │ │   │
│  │  │ (Gemini) │ │ (SQLite) │ │                  │ │   │
│  │  └──────────┘ └──────────┘ └──────────────────┘ │   │
│  │                                                  │   │
│  │  Tools (7):                                      │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐   │   │
│  │  │ CloudTrail │ │  VPC Flow  │ │ Auth Logs  │   │   │
│  │  └────────────┘ └────────────┘ └────────────┘   │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐   │   │
│  │  │   Config   │ │     IP     │ │   Alert    │   │   │
│  │  │   Audit    │ │ Reputation │ │ Generator  │   │   │
│  │  └────────────┘ └────────────┘ └────────────┘   │   │
│  │              ┌────────────────┐                  │   │
│  │              │  Remediation   │                  │   │
│  │              └────────────────┘                  │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────┘
                       │
         ┌─────────────▼─────────────┐
         │      DATA LAYER           │
         │  cloudguard.db            │
         │   ├─ chat_messages        │
         │   └─ alerts               │
         │  agent_memory.db          │
         │   └─ langgraph checkpoints│
         │  Sample logs (JSON)       │
         └───────────────────────────┘
```

### Agent Akışı (ReAct döngüsü)

1. **Thought** — Kullanıcı mesajını analiz eder, hangi tool'u çağırması gerektiğine karar verir
2. **Action** — İlgili tool'u uygun argümanlarla çağırır
3. **Observation** — Tool çıktısını alır, gerekirse başka bir tool'u zincirleme çağırır
4. **Response** — Tüm bulguları Türkçe, MITRE referanslı, severity sınıflandırılmış bir cevap olarak özetler

Her tur, thread bazlı bir checkpointer'a kaydedilir — uvicorn restart edilse bile konuşma kaldığı yerden devam eder.

---

## Tech Stack

| Katman | Teknoloji |
|---|---|
| LLM | Google Gemini 2.5 Flash (ücretsiz tier) |
| Agent | LangChain 1.x + LangGraph 1.x |
| Backend | FastAPI 0.136 + Uvicorn |
| Frontend | React 19 + Vite 8 + Tailwind v4 |
| Veritabanı | SQLite (SQLAlchemy 2.x ORM) |
| Threat Intel | AbuseIPDB + VirusTotal API'leri (opsiyonel) |
| Container | Docker Compose (multi-stage build) |
| CI/CD | GitHub Actions (ruff + pytest) |

---

## Hızlı Başlangıç

### Ön gereksinimler

- Docker Desktop (önerilen) **veya** Python 3.11+ ve Node.js 20+
- Google Gemini API key — [aistudio.google.com/apikey](https://aistudio.google.com/apikey) (ücretsiz)

### 1. Repo'yu klonla

```bash
git clone https://github.com/<KULLANICI>/cloudguard-ai.git
cd cloudguard-ai
```

### 2. Environment ayarla

Repo köküne `.env` dosyası oluştur:

```env
GEMINI_API_KEY=AIza...                # zorunlu
ABUSEIPDB_API_KEY=                    # opsiyonel (boşsa demo mode)
VIRUSTOTAL_API_KEY=                   # opsiyonel
```

### 3. Docker ile çalıştır

```bash
docker compose up --build
```

Hazır olduğunda:

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **Swagger UI**: http://localhost:8000/docs

Durdurmak için `Ctrl+C`, sonra `docker compose down`.

### 4. Demo soruları

Frontend'i açtıktan sonra şu soruları sırayla deneyebilirsin:

1. *"Son CloudTrail loglarında şüpheli aktivite var mı?"*
2. *"203.0.113.45 IP'si güvenli mi?"*
3. *"AWS yapılandırmamızı denetle, S3, security group, IAM ve RDS'de açık var mı?"*
4. *"Linux sunucularımıza SSH brute force saldırısı oldu mu?"*
5. *"Bu bulgular için müdahale planı çıkar."*

---

## Geliştirme

### Backend (lokal, Docker'sız)

```bash
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1   # Windows
# source venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
cp .env.example .env           # API key'leri doldur
python -m uvicorn app.main:app --reload
```

### Frontend (lokal, Docker'sız)

```bash
cd frontend
npm install
npm run dev
```

Frontend `localhost:5173`'te açılır, `/api/*` istekleri Vite proxy üzerinden backend'e iletilir.

### Veritabanını sıfırlama

```bash
cd backend
python -c "from app.db.database import engine; from app.db.models import Alert; Alert.__table__.drop(engine, checkfirst=True); print('alerts table dropped')"
```

Veya tüm DB için: `backend/data/cloudguard.db` ve `agent_memory.db` dosyalarını sil.

---

## Güvenlik Araçları

CloudGuard AI 7 farklı güvenlik aracı içerir. Agent kullanıcının sorusuna göre uygun tool(lar)ı kendisi seçer.

### 1. `analyze_cloudtrail_logs`

AWS CloudTrail loglarını analiz eder. Tespit ettiği olaylar:

- **Brute force console login** — Aynı IP'den 3+ başarısız `ConsoleLogin` (3 → MEDIUM, 5+ → HIGH). 3 sınırı seçildi çünkü AWS GuardDuty'nin kendi "Stealth.IAMUser/PasswordPolicyChange" baseline'ı 3+ failure'ı eşik kabul ediyor.
- **Privilege escalation** — IAM modifikasyonları: `AttachUserPolicy`, `CreateAccessKey`, `PutUserPolicy`, `CreateRole`, `UpdateAssumeRolePolicy`. AdministratorAccess attach'ı ayrı CRITICAL daldır.
- **Unauthorized access** — `errorMessage` içinde "Unauthorized" / "AccessDenied" — sızdırılmış key probing'in en net sinyali.
- **S3 public exposure** — `PutBucketPolicy` ya da `PutBucketAcl` çağrıları, sonrasında politika gerçekten public mi kontrol edilir.
- **S3 mass object access** — Aynı bucket'a 60s içinde 10+ `GetObject` çağrısı (data exfiltration paterni). 60 saniyelik pencere AWS Macie'nin mass-download alarm pencereleriyle uyumludur.

### 2. `analyze_vpc_flow_logs`

VPC Flow Logs üzerinde ağ tabanlı anomali tespiti:

- **Port scan** — Tek kaynak IP'nin 5+ farklı portu denemesi ve %50+ REJECT alması. 5 port eşiği nmap'in default `-F` (fast scan) profiline yakın bir alt sınır; `%50 REJECT` koşulu meşru çoklu-servis bağlantısını (örn. bir web sunucunun hem 443 hem 80'e doğru istek çıkarması) port scan'den ayırmak için.
- **SSH brute force (ağ katmanı)** — Port 22'ye dış IP'den 10+ flow. Auth log analiziyle çakışırsa CRITICAL'a yükselir.
- **Data exfiltration** — Tek bir iç IP'den dış IP'ye ≥ 100 MB outbound flow. 100 MB sınırı sample data'daki en yüksek "normal" flow'un (8 KB) ~12 800 katı; gerçek üretim ortamlarında değer sysadmin tarafından konfigüre edilmeli ama demo için net ayırıcı.

### 3. `analyze_auth_logs`

Linux `/var/log/auth.log` analizi:

- **SSH brute force** — Aynı IP'den 5+ başarısız `sshd` kimlik doğrulaması (5 → MEDIUM, 10+ → HIGH). CIS Benchmark'ın 4-6 başarısız deneme tavsiyesinin orta değeri.
- **SSH compromise** — `Failed password` → `Accepted password` korelasyonu, **120 saniye pencere** içinde. 120s eşiği: 60s çok dar (yavaş bot'ları kaçırır), 300s çok geniş (meşru kullanıcı parolasını yanlış girip 5 dk sonra başarılı denemeyle false positive üretir). 120s, gerçek brute-force botlarının saniyede onlarca denemesinin tamamlanma penceresi olarak ampirik bir orta yol.
- **Sudo escalation attempts** — Aynı kullanıcıdan 3+ başarısız `sudo` (sudo log'da `incorrect password attempts` mesajıyla).

### 4. `audit_cloud_config`

Sentetik AWS Config snapshot üzerinde misconfiguration denetimi:

- **S3:** Public access, encryption-at-rest, versioning, access logging
- **Security Groups:** SSH (22), RDP (3389), DB ports, geniş port aralıkları 0.0.0.0/0'a açık mı
- **IAM:** Admin user MFA durumu, eski access key'ler, kullanılmayan key'ler
- **RDS:** Public accessibility, encryption, backup retention

Findings `correlation_hint` field'ı ile log analizinden çıkan saldırılarla eşleştirilir — "bu misconfig aktif olarak sömürüldü" sinyali için.

### 5. `check_ip_reputation`

IP threat intelligence sorgusu. İki ana kaynak:

- **AbuseIPDB** — abuse confidence score (0-100), TOR exit node flag, ISP, ülke
- **VirusTotal** — malicious vendor count, AS owner, reputation skoru

İki kaynağı birleştirip tek threat level üretir (CRITICAL / HIGH / MEDIUM / LOW). Bir kaynak CRITICAL derse VirusTotal "harmless" dese bile **asla downgrade etmez** — güvenlik prensibi olarak doğru.

API key yoksa **demo mode** devreye girer: sample log'lardaki bilinen attacker IP'lerine local lookup table'dan cevap döner. Bu sayede uçtan uca demo internet bağlantısı veya API key olmadan da yapılabilir.

### 6. `generate_alert`

Bulgu yapılandırılmış bir alert kaydı olarak DB'ye yazar. Otomatik olarak:

- Finding type'ı kanonik kategoriye normalize eder (`BRUTE_FORCE_CONSOLE_LOGIN` → `BRUTE_FORCE`)
- MITRE ATT&CK metadata'sı ekler (technique ID, tactic, technique adı)
- Severity'yi doğrular (CRITICAL/HIGH/MEDIUM/LOW dışını LOW'a indirir)

Frontend dashboard'u bu tabloyu okuyup canlı gösterir.

### 7. `get_remediation`

Finding type'a göre 3 fazlı müdahale playbook'u döndürür:

- **IMMEDIATE** — saatler içinde (containment)
- **INVESTIGATION** — 24-48 saat içinde (scoping)
- **LONG_TERM** — haftalar içinde (prevention)

Bu yapı NIST SP 800-61 Incident Response lifecycle'a uygundur. Her playbook adımı opsiyonel AWS CLI / shell komutuyla gelir; agent context bilgisini geçirirse (örn. `bucket=prod-customer-data`) komutlardaki placeholder'lar gerçek değerle değişir.

### MITRE ATT&CK Eşleştirmesi

| Finding Type | Technique | Tactic |
|---|---|---|
| BRUTE_FORCE | T1110 | Credential Access |
| PRIVILEGE_ESCALATION | T1098 | Persistence |
| UNAUTHORIZED_ACCESS | T1078 | Initial Access |
| SSH_COMPROMISE | T1078 | Initial Access |
| SUDO_ESCALATION | T1548 | Privilege Escalation |
| S3_PUBLIC_EXPOSURE | T1530 | Collection |
| DATA_EXFILTRATION | T1048 | Exfiltration |
| NETWORK_RECON | T1046 | Reconnaissance |
| SECURITY_GROUP_MISCONFIG | T1133 | Initial Access |
| IAM_HYGIENE | T1078 | Persistence |
| RDS_EXPOSURE | T1530 | Collection |

---

## API Endpoint'leri

| Method | Path | Açıklama |
|---|---|---|
| `GET` | `/` | Sağlık check, app metadata |
| `GET` | `/health` | Detaylı health check |
| `POST` | `/chat` | Agent'a mesaj gönder, `{reply, tool_calls}` al |
| `GET` | `/history` | Konuşma geçmişi (thread filter, limit) |
| `GET` | `/alerts` | Alert listesi + severity sayımları |

Detaylı şema için: http://localhost:8000/docs (Swagger UI)

### `POST /chat` örnek

```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Son loglarda şüpheli aktivite var mı?",
    "thread_id": "demo-1"
  }'
```

Response:

```json
{
  "reply": "CloudTrail loglarında 14 bulgu tespit edildi...",
  "thread_id": "demo-1",
  "tool_calls": [
    {"name": "analyze_cloudtrail_logs", "args": {"query": "all"}},
    {"name": "generate_alert", "args": {"finding_type": "BRUTE_FORCE", "severity": "HIGH"}}
  ]
}
```

---

## Test ve CI

### Lokal test

```bash
cd backend
ruff check app/         # Lint
pytest tests/ -v        # Unit test
```

### CI Pipeline

GitHub Actions her `push` ve `pull_request`'te otomatik çalışır:

- **Ruff lint** — `app/` altında E, W, F, I, B kuralları
- **Pytest** — Temel sağlık testleri (config, endpoint'ler, validation)

`main` branch korumalı: PR + CI yeşil olmadan merge edilemez.

---

## Dosya Yapısı

```
cloudguard-ai/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI app, lifespan, CORS
│   │   ├── config.py                  # Settings (.env)
│   │   ├── agent/
│   │   │   ├── core.py                # LangGraph agent + chat() fonksiyonu
│   │   │   ├── prompts.py             # System prompt
│   │   │   └── tools/
│   │   │       ├── log_analyzer.py    # CloudTrail/VPC/Auth analiz (3 sub-tool)
│   │   │       ├── ip_reputation.py   # AbuseIPDB + VirusTotal
│   │   │       ├── config_auditor.py  # AWS misconfig audit
│   │   │       ├── alert_generator.py # Alert persistence
│   │   │       └── remediation.py     # 3-faz playbook
│   │   ├── api/
│   │   │   ├── routes.py              # /chat, /history, /alerts
│   │   │   └── schemas.py             # Pydantic models
│   │   └── db/
│   │       ├── database.py            # SQLAlchemy engine + session
│   │       └── models.py              # ChatMessage, Alert
│   ├── data/
│   │   ├── sample_logs/               # Test verisi (cloudtrail/vpc/auth JSON)
│   │   ├── cloudguard.db              # Chat history + alerts
│   │   └── agent_memory.db            # LangGraph checkpoints
│   ├── tests/
│   ├── requirements.txt
│   ├── pyproject.toml                 # Ruff + pytest config
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.jsx          # Sol/sağ split layout
│   │   │   ├── ChatInterface.jsx      # Chat UI
│   │   │   ├── MessageBubble.jsx      # Mesaj balonları + tool rozetleri
│   │   │   ├── AlertPanel.jsx         # Alert listesi
│   │   │   ├── SeverityChart.jsx      # Recharts donut
│   │   │   └── ToolActivity.jsx       # Tool kullanım feed'i
│   │   ├── services/
│   │   │   └── api.js                 # Backend client
│   │   └── App.jsx
│   ├── nginx.conf                     # Production proxy config
│   ├── package.json
│   └── Dockerfile                     # Multi-stage (build + nginx)
├── docker-compose.yml
├── .github/workflows/ci.yml
├── docs/
│   ├── ai-log-yunus.md                # Yunus AI kullanım günlüğü
│   ├── ai-log-sec.md                  # Security AI kullanım günlüğü
│   └── rapor.pdf                      # Final rapor
└── README.md
```

---

## Geliştiriciler

| İsim | Sorumluluk |
|---|---|
| **Yunus** | Backend (FastAPI, agent core), Frontend (React, dashboard), DevOps (Docker, CI) |
| **Sena** | Security tools (log analyzer, IP reputation, config auditor, alert generator, remediation), Sample data, Detection rules, MITRE mapping |

---

## Bilinen Limitasyonlar

- **Recall over precision:** Detection kuralları yüksek hassasiyet değil, yüksek tespit oranı için ayarlanmış. Demo'da bilinçli olarak false positive görebilirsin (örn. legitimate IAM admin onboarding flag'lenir).
- **Sentetik veri:** Tüm analizler `backend/data/sample_logs/`'daki örnek dosyalar üzerindedir; gerçek AWS hesabı bağlantısı yoktur.
- **Demo mode IP reputation:** API key olmadan sadece sample data'daki bilinen IP'ler için anlamlı cevap döner.
- **Free tier rate limit:** Gemini 2.5 Flash ücretsiz tier 10 RPM / 250 RPD ile sınırlı. Yoğun test sırasında 429 alınabilir.

---

## Yararlanılan Kaynaklar

- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST SP 800-61 — Computer Security Incident Handling](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [Gemini API Documentation](https://ai.google.dev/gemini-api/docs)