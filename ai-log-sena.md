# AI Kullanım Günlüğü — Security

## Giriş

Bu belge, CloudGuard AI projesinde güvenlik tool'larını ve sample
veriyi geliştirirken yapay zeka araçlarını (ağırlıklı olarak Claude)
nasıl kullandığımı kaydeder. Her kayıtta: hedefim neydi, AI'a ne
sordum, çıktıyı nasıl değerlendirdim, nerede yanıldı, ben nasıl
düzelttim, bu süreçten ne öğrendim.

Amaç: AI'ı bir "otomatik kod yazıcı" olarak değil, beraber çalıştığım
bir mimar/danışman gibi kullandığımı göstermek. Kararlar bana ait,
AI sadece seçenek üretiyor ve hızlandırıcı rol oynuyor.

---

## Log #1
**Tarih:** 2026-04-22
**Aşama:** CloudTrail sample data tasarımı (Görev 1.1)
**Kullanılan AI aracı:** Claude

### Ne yapmaya çalıştım?
`backend/data/sample_logs/cloudtrail_sample.json` dosyasını oluşturmak.
Tool'umuzun (`log_analyzer`) test edebileceği, hem saldırı hem normal
trafik içeren, gerçekçi bir CloudTrail örneği lazımdı. Görev dosyası
"30-50 kayıt" hedefi vermişti ama hangi senaryoları, hangi oranda,
hangi tutarlılıkla koyacağımı tasarlamam gerekiyordu.

### Verdiğim prompt:
AI'a tek bir büyük prompt vermedim — adım adım tasarım yaptırdım.
Yaklaşımım şuydu:

1. "Sample data için hangi senaryolar olmalı, neden?" — beyin fırtınası
2. Her senaryo için: aktör, IP, zaman, event sayısı kararı (ben verdim)
3. AI'a "bu senaryo gerçekçi mi, eksiği var mı?" diye danıştım
4. Sonunda generator script + JSON üretildi

Tasarım kararlarının özeti:

- **5 senaryo:** brute force (S1), privilege escalation (S2),
  S3 exfiltration (S3), leaked-key probing (S4), normal traffic (S5)
- **Toplam 46 event** (50 hedefine yakın, 30 minimumun üstünde)
- **S1+S2+S3 zincirli:** aynı saldırgan IP'sinden (203.0.113.45),
  8.5 dakika içinde brute force → compromise → privesc → exfil.
  Bu klasik bir "kill chain" — gerçek breach raporlarında görülen pattern.
- **S4 ayrı incident:** farklı saldırgan, farklı zaman (12:00),
  ayrı motivasyon (sızdırılmış API key). Bu sayede tool'un birden
  fazla bağımsız incident'i ayırt edebildiğini test edebiliriz.
- **2 kasıtlı false positive:** S2'nin içinde meşru bir admin
  aktivitesi (yeni çalışan onboarding'i) ekledik. Mevcut detection
  bunu CRITICAL flag'leyecek — bu kasıtlı, raporda
  "tool limitation + future work" tartışması için malzeme.
- **dev-user baseline:** dev-user'ın sabah 08:45'te eu-west-1 ofis
  IP'sinden ve normal browser ile login olduğunu gösteren 2 event
  ekledik. Öğleden sonraki compromise (us-east-1, python-requests UA)
  bu sayede net bir anomali olarak okunuyor.

### AI'ın cevabı işe yaradı mı?

**✅ Çalışan kısımlar:**
- Senaryo seçim listesi mantıklıydı (brute force, privesc, S3,
  unauthorized — hepsi gerçekçi tehditler)
- AWS event name'leri büyük çoğunlukla doğruydu
  (AttachUserPolicy, CreateAccessKey, GetBucketAcl vb. resmi API isimleri)
- MITRE ATT&CK eşlemeleri (T1110, T1098, T1530) doğru
- TEST-NET-3 (203.0.113.0/24) ve doc range (198.51.100.0/24)
  gibi sahte veri için güvenli IP aralıklarını önerdi

**❌ Çalışmayan / dikkat ettiğim kısımlar:**
- AI başlangıçta "tek saldırgan, tek hedef" gibi basit bir senaryo
  önerdi. Bu detection'ın sadece bir branch'ini test ederdi.
  Ben "iki saldırgan + zincir + paralel incident" yapısına yönlendirdim.
- AI "false positive ekleyelim mi?" sorusunda iki seçeneği de
  eşit sundu. Halbuki rapor için meşru aktivite eklemek **çok daha
  değerli** — limitations bölümünde somut malzeme oluyor. Bu kararı
  ben verdim, AI'a değil.
- İlk doğrulama script'imde `userIdentity['userName']` kullandım
  ama AssumedRole tipinde bu alan farklı yerde
  (`sessionContext.sessionIssuer.userName`). Test sırasında KeyError
  aldım — gerçek CloudTrail schema'sının iki tipi olduğunu
  hatırlatan iyi bir hata.

### Hatayı nasıl tespit ettim?
- Generator çalıştıktan sonra dağılım kontrolü yaptım: scenario tag'leri
  saydım, beklediğim sayılarla (S1=7, S2=7, S3=7, S4=7, S5=18) eşleştir.
- Detection logic'ini sample'a karşı simule ettim — `log_analyzer`'ın
  hangi event'leri yakalayacağını manuel olarak hesaplayıp doğruladım.
- Brute force'ta beklenen 7 değil 6 fail flag'lendi — fark sebebi:
  7. event başarılı login olduğu için `responseElements.ConsoleLogin`
  "Success", "Failure" değil. Doğru davranış. Kafamda bir an
  "bug mu var?" dedim, sonra fark ettim.

### Nasıl düzelttim?
- AssumedRole hatası: doğrulama helper'ında
  `ui.get('userName') or ui.get('sessionContext', ...)` fallback ekledim.
- Senaryolarda derinlik eksikliği: AI'ın "minimal" önerilerini
  reddedip her senaryo için 7 event aldım. Tek bir
  AttachUserPolicy event'i değil, tam bir privesc zinciri
  (persistence + primary + backdoor + redundancy).
- AI'ın bana "JSON dosyasını direkt yazayım mı?" önerisi vardı.
  Kabul etmedim, generator script + JSON çıktısı şeklinde istedim.
  Sebep: generator script tasarım kararlarını kod yorumlarıyla
  belgeleyebilir, raporda referans olur. JSON tek başına "kod yazılmış"
  hissi verirdi.

### Bu deneyimden ne öğrendim?
1. **Sample data bir test case'tir, rasgele veri değil.** Her event'in
   bir amacı olmalı — ya bir detection branch'ini doğruluyor, ya bir
   limitation'ı gösteriyor, ya bir gelecek özelliği için seed.
2. **Kill chain tasarlamak tek tek event'lerden daha öğretici.** Brute
   force tek başına bir bulgu, ama brute force → privesc → exfil
   zinciri "ne kadar kötü bir gün olabilirdi" hikâyesi anlatıyor.
   Demo'da çok daha güçlü.
3. **AI iyi bir "seçenek üreticisi" ama kötü bir karar verici.**
   "False positive eklensin mi?" gibi tasarım kararlarında AI
   tarafsız sundu — karar değerini ben görmek zorundaydım.
   Rapora "AI ile mimari karar" diye yazılacak şey tam bu.
4. **CloudTrail schema'sı IAMUser ve AssumedRole için farklı.**
   `userIdentity.userName` her zaman olmuyor; servis hesapları
   için `sessionContext` üzerinden gitmek lazım. Tool kodunda
   bu farkı handle etmek gerekecek.

---

## Log #2
**Tarih:** 2026-04-22
**Aşama:** VPC Flow Logs sample data tasarımı (Görev 1.1 devamı)
**Kullanılan AI aracı:** Claude

### Ne yapmaya çalıştım?
`backend/data/sample_logs/vpc_flowlogs_sample.json` dosyasını üretmek.
CloudTrail'den çok farklı bir log türü: network paketi seviyesi
(IP, port, byte sayısı), uygulama seviyesi değil. Tasarım: 4 senaryo
(port scan, SSH brute force, data exfil, normal) — toplam 38 kayıt.

### Verdiğim prompt (özet):
"VPC Flow Log v2 schema'sını ver, yaygın network saldırılarını
tasarlayalım. Senaryo başına net detection sinyali olsun, threshold'lar
kafamdan değil 'normal trafiğin kaç katı' mantığıyla belirlensin."

### AI'ın cevabı işe yaradı mı?

**✅ Çalışan kısımlar:**
- VPC Flow Log v2 schema'sını (version, account_id, srcaddr, dstaddr,
  srcport, dstport, protocol, packets, bytes, start, end, action,
  log_status) doğru hatırladı.
- Saldırı pattern'lerinin gerçekçi parametreleri konusunda iyi rehber:
  port scan'de SYN-only paketler (~44 byte), SSH brute force'ta küçük
  ama hızlı flow'lar, exfil'de sustained yüksek hacim.
- Protocol numaralarını doğru verdi (6=TCP, 17=UDP, 1=ICMP).

**❌ Çalışmayan / dikkat ettiğim kısımlar:**
- AI önerdiği exfil eşiği "100 MB" gibi soyut bir sayıydı. Bunu
  reddedip "normal trafiğin kaç katı?" diye düşündüm. Sample'da en
  büyük normal flow ~8 KB; en küçük exfil ~512 MB → **65.472x oranı**.
  Bu somut sayı raporda threshold gerekçesi olarak çok daha güçlü
  durur ("100 MB" mertebesi rastgele bir tahmindir).
- AI ilk önerisinde V2 SSH brute force için **REJECT** kullanmıştı.
  Ama düşününce mantık şu: gerçek brute force'ta security group
  port 22'yi açıyor (yoksa saldırgan zaten ulaşamaz), reddeden
  uygulama (sshd) oluyor. Yani **VPC ACCEPT, auth_logs FAIL**.
  Bu cross-source correlation insight'ı önemli — AI bunu vurgulamadı,
  ben fark ettim. Auth logs'u tasarlarken aynı IP'yi kullanacağım
  (45.142.213.50) ki iki log dosyası bir araya getirildiğinde
  saldırı net görünsün.
- AI ENI (Elastic Network Interface) atamasını eksik yaptı.
  ENI internal tarafa bağlıdır; akış inbound ise dst, outbound ise
  src tarafındaki ENI loglara düşer. Bunu generator helper'ında
  manuel handle ettim.

### Hatayı nasıl tespit ettim?
- Generator'ı çalıştırıp dağılım kontrolü: V1=12, V2=8, V3=3, V4=15.
- Detection sinyallerini manuel hesaplattım:
  - V1: 12 farklı port, %75 REJECT — clear scan
  - V2: 8 flow port 22, 44 saniyede — clear brute force
  - V3: 2.96 GB toplam, normal max'ın 65.472 katı — clear exfil
- Threshold'ları "normal max"a göre relatif kontrol etmek **AI'ın
  önerdiği mutlak sayılardan daha sağlam** çıktı.

### Nasıl düzelttim?
- Exfil byte miktarlarını kasıtlı olarak normal trafikten çok yüksek
  yaptım: 512 MB / 1 GB / 1.5 GB. Normal max ~8 KB. Aradaki uçurum
  detection için tek bir basit kuralı (`bytes > 100 * 1024 * 1024`)
  yeterli kılıyor.
- V2'yi REJECT yerine ACCEPT yaptım ve ai-log'a not düştüm:
  "auth_logs'ta aynı IP fail'leri görünmeli."
- Generator'a `random.seed(42)` ekledim — source port'lar
  rastgele ama her çalıştırmada aynı, testler tutarlı olsun.
- DAY_BASE'i CloudTrail ile aynı güne (2026-04-21) sabitledim
  → iki log dosyası aynı güne ait, gerçekçi.

### Bu deneyimden ne öğrendim?
1. **Threshold'lar baseline'a göre belirlenmeli, kafadan değil.**
   "100 MB ne zaman kötü?" sorusunun cevabı ortama bağlı. Bizim
   sample'da normal max 8 KB ise 100 MB zaten çok yüksek; başka
   bir ortamda 100 MB rutin olabilir. Tool yazarken `THRESHOLD_BYTES`
   gibi configurable bir sabit yapıp default verip dökümante etmek
   doğru olur.
2. **Cross-source correlation log analizinin ruhudur.** VPC ACCEPT
   tek başına bir şey demez — auth_logs'taki fail ile birleşince
   anlam kazanır. Hafta 3'te tool'lar arası correlation eklemek
   buradan başlayabilir.
3. **Reproducibility önemsiz değil.** `random.seed(42)` olmasaydı
   her testte source port'lar farklı çıkar, bug üretirdi. Sample
   data'nın ne kadar deterministik olduğu = ne kadar güvenilir
   test edebileceğin demek.
4. **VPC ve CloudTrail tek bir hikâye anlatır ama farklı kameralardan.**
   Aynı saldırı CloudTrail'de "kim hangi API'yi çağırdı"yı, VPC'de
   "kim hangi paketi gönderdi"yi gösterir. Demo'da agent'ın iki
   kaynağı birleştirmesi etkileyici olacak.

---

## Log #3
**Tarih:** 2026-04-22
**Aşama:** auth_logs sample data + VPC ile cross-correlation kurma (Görev 1.1)
**Kullanılan AI aracı:** Claude

### Ne yapmaya çalıştım?
`backend/data/sample_logs/auth_logs_sample.json` dosyasını üretmek.
Bu dosyanın özel görevi: VPC V2 SSH brute force senaryosuyla **cross-source
correlation** kurmak. Tek başına anlamlı bir saldırı olduğu kadar, VPC
flow log'larıyla birleştirildiğinde "tam SSH compromise" hikâyesini
anlatmalı. Toplam 25 event, 4 senaryo.

### Verdiğim prompt (özet):
"VPC V2'deki 8 SSH flow'u (45.142.213.50 → 10.0.1.50:22, 13:00-13:00:42)
auth.log tarafında 1:1 eşleşmeli. Ama VPC ACCEPT diyor, auth_logs ne
diyecek? Klasik brute force: 7 fail + 1 success. 8. denemede saldırgan
zayıf şifreyi (ubuntu kullanıcısı) buluyor → compromise. Sonra sudo ile
yetki yükseltmeyi deniyor, ona izin yok."

### AI'ın cevabı işe yaradı mı?

**✅ Çalışan kısımlar:**
- Linux auth.log formatını (sshd, sudo, pam_unix, login servisleri)
  doğru biliyordu.
- "Failed password", "Accepted publickey", "Invalid user", "session
  opened" gibi event isimleri gerçek auth.log'dan birebir.
- ubuntu user'ın AWS Ubuntu AMI'lerinde default user olduğunu ve
  sıkça zayıf şifreli bırakıldığını doğru hatırladı — gerçekçi
  vulnerability vektörü.

**❌ Çalışmayan / dikkat ettiğim kısımlar:**
- AI başlangıçta tek tip sshd event önerdi: hep "Failed password".
  Gerçek auth.log'da çeşit var: "Invalid user X" (kullanıcı sistemde
  yok), "Failed password" (var ama yanlış), "Connection closed by
  authenticating user X [preauth]" (handshake fail). A4 noise'a
  "Invalid user oracle" ekleyerek bu çeşitliliği gösterdim.
- AI 8 brute force denemesi içinde 8 farklı kullanıcı önerdi —
  ama gerçek attacker'lar **aynı kullanıcıya birden fazla şifre**
  dener (ubuntu için 3 deneme yaptım, 3.'sü hit). Bu daha gerçekçi
  hem de "şifre sözlüğü deniyor" hissi veriyor.
- AI sudo failure'ları için "user not in sudoers" mesajı önerdi
  ama event format'ım "FAILED sudo command" + command parametresi
  şeklindeydi (basitleştirme için). İki yaklaşımı karıştırmamak
  lazım — schema'yı en başta sabitleyip her event'te aynı tutmak
  daha temiz oldu.

### Hatayı nasıl tespit ettim?
- Cross-correlation kontrolü: VPC sample'ı yükleyip, auth_logs ile
  yan yana saldırgan IP'sinden gelen event sayısı, zaman penceresi,
  hedef port'u karşılaştırdım.
  - VPC: 8 flow, 13:00:00-13:00:44
  - Auth: 8 sshd event (7 fail + 1 success), 13:00:00-13:00:42
  - **Mükemmel eşleşme** ✓
- A4 noise threshold'u kontrol: tek-deneme'lik internet noise'unun
  brute-force detection'ı tetiklememesi gerek. Tek IP'den ≥3
  threshold'u standart, sample'da 1+1=2 IP, her biri 1 deneme →
  Hiçbir alarm tetiklenmez ✓.

### Nasıl düzelttim?
- 8 brute force denemesini 5 farklı user'a yaydım (root, admin,
  ubuntu×3, postgres, ec2-user) — sözlük saldırısı hissi.
- Schema'yı sabitledim: her event aynı 8 alana sahip
  (timestamp, hostname, service, event, user, source_ip, port, success).
  Sudo'da source_ip null, sshd'de dolu — bu mantıklı.
- Subtle realism eklemeleri: 14:30'da devops-eng'in incident response
  için web-server-01'e SSH ile giriş yapması, 14:35'te aynı kişinin
  `grep -i error /var/log/auth.log` çalıştırması. Saldırı sonrası
  insanların ne yaptığını gösteriyor. Bu detaylar sample'ı **gerçekçi
  bir günün auth.log'una** dönüştürüyor — sadece test verisi gibi
  durmuyor.

### Bu deneyimden ne öğrendim?
1. **Cross-source correlation = tek başına okumayan sinyal.**
   VPC ACCEPT tek başına "saldırı" demez. Auth_logs FAIL tek başına
   "compromise" demez. Birleşince hikâye netleşir. Tool tasarımında
   bu vektörü Hafta 3'te ekleyeceğim — şimdiden sample'da hazır.
2. **Sample data anlatı kalitesinde olmalı.** "13:00 saldırı, 14:30
   incident response, 14:35 log inceleme" gibi mikrodetaylar verinin
   gerçekçiliğini katlıyor. Demo'da agent bu ayrıntıları yakalarsa
   "düşünüyor" hissi veriyor — yakalamasa bile hocanın okuyacağı
   sample'da görünüyor.
3. **Schema sabitliği ≫ esneklik.** Generator'da "sshd için şöyle,
   sudo için böyle" yapmak yerine tek `make_*` helper'ı tek schema
   ile çalışmalı. Tool kodu da bu sayede tek şablona göre yazılır.
4. **AWS Ubuntu AMI vulnerability vektörü gerçek bir tehdit.**
   Default user (`ubuntu`) + zayıf şifre + public IP + SSH açık SG
   = compromise reçetesi. Bunu rapora "real-world vector"
   olarak yazabilirim.

---

## Log #4
**Tarih:** 2026-04-23
**Aşama:** log_analyzer.py — 3 @tool fonksiyonu (Görev 1.2)
**Kullanılan AI aracı:** Claude

### Ne yapmaya çalıştım?
`backend/app/agent/tools/log_analyzer.py` dosyasını yazmak. 3 ayrı
`@tool` fonksiyonu: `analyze_cloudtrail_logs`, `analyze_vpc_flow_logs`,
`analyze_auth_logs`. Her biri kendi log dosyasını okuyup detection
kurallarını uygulayıp Markdown rapor döndürecek. Sample veriyi önceden
tasarladığım için tool'u yazıp **anında test edebildim**.

### Verdiğim prompt (özet):
"3 ayrı tool yazalım, tek parametreli mega-tool yerine. Her birinin
docstring'i ne yaptığını ve agent'ın hangi sorularda çağıracağını
açıkça belirtsin. Threshold'lar sample baseline'a göre ayarlansın
ve named constant olsun. Output Markdown — chat UI'da renderable."

### AI'ın cevabı işe yaradı mı?

**✅ Çalışan kısımlar:**
- LangChain `@tool` decorator pattern'ini doğru kullandı.
- Docstring formatını agent-routing için optimal yazdı: "Use this
  tool when the user asks about..." şeklinde explicit triggers.
- `defaultdict(list)` ile event grouping, MITRE mapping dict gibi
  Python idioms'lerini uygun yerlerde önerdi.

**❌ Çalışmayan / dikkat ettiğim kısımlar:**
- AI tek büyük `@tool(log_type: str)` fonksiyonu önerdi başlangıçta
  ("kod tekrarını azaltır" dedi). Bunu reddettim. Sebep: LangChain
  ReAct agent'ı tool seçimini docstring'e göre yapar. Tek tool +
  parametre = agent'ın "log_type=cloudtrail mı vpc mı?" diye karar
  vermesi gerekiyor — bu zayıf bir sinyal, hata olasılığı yüksek.
  3 ayrı tool = 3 ayrı net amaç = daha iyi routing. Best practice
  diye not düştüm.
- AI ilk versiyonda `query` parametresini detection mantığında
  kullanmaya çalıştı (kullanıcının "iam events" gibi filtre verdiği
  varsayımıyla). Şu an için aşırı karmaşıklık — LLM zaten doğru
  tool'u seçti ya, parsing yapmaya gerek yok. Parametreyi tuttum
  ama informational yaptım, docstring'de "currently informational
  only" yazdım. Hafta 3'te query parsing eklenebilir.
- Threshold sayılarını AI önerdi ama gerekçesiz (örn: "SSH brute force
  threshold 10 olsun"). Ben her threshold'u kod yorumuyla **sample
  baseline'dan türettim**: "VPC EXFIL_BYTES_THRESHOLD = 100 MB,
  rationale: en büyük normal flow 8 KB, 100 MB = 12.800x — net
  ayrım." Bu yorumlar raporda thresholds tartışması için doğrudan
  malzeme.
- AI ilk versiyonda `userIdentity['userName']` direkt erişti — ama
  AssumedRole tipinde bu alan yok. Önceki Log #1'de bulduğum bug'ı
  hatırlayıp `_ct_user_of()` helper'ında handle ettim:
  ```python
  ui.get("userName") or ui.get("sessionContext", {})\
      .get("sessionIssuer", {}).get("userName") or "unknown"
  ```
- AI `success: bool` field'ı için fallback değerini False yapmıştı.
  Bu bug yaratırdı çünkü auth_logs'taki PAM session opened event'inde
  `success` alanı var (True), ama A2/A3 normal events'te olmasa default
  False döner ve normal aktivite "fail" gibi görünür. Default'u
  `True` yaptım — "explicit fail" mantığı.

### Hatayı nasıl tespit ettim?
- **Sample veriye karşı çalıştırarak.** Bu en değerli adım.
  CloudTrail'ı çalıştırdım — beklediğim 14 finding geldi (5 privesc +
  2 false positive + 1 brute + 4 unauthorized + 1 public bucket +
  1 mass access). VPC'yi çalıştırdım — beklediğim 5 finding (3 exfil +
  port scan + SSH brute). Auth'u çalıştırdım — beklediğim 3 finding
  (compromise + brute + sudo).
- **A4 noise'un alarm üretmediğini** ayrıca doğruladım. Tek-deneme'lik
  internet noise threshold'un altında kaldı. True negative ✓.
- **S5 normal traffic'ın alarm üretmediğini** doğruladım. 18 normal
  CloudTrail event, 15 normal VPC flow, 8 normal SSH login, 4 normal
  sudo — hiçbiri flag'lenmedi.

### Nasıl düzelttim?
- Tool ayırma kararı: 3 ayrı @tool. Her birinin docstring'i
  "Use this tool when the user asks about..." pattern'iyle başlıyor.
  Agent için kristal-net routing.
- `query` parametresi default değerli (`"all"`) — hem agent invoke
  edebiliyor hem boş bırakabiliyor.
- `_format_report` fonksiyonunu helper olarak çıkardım. 3 tool'un
  hepsi aynı output şablonunu kullanıyor — DRY ve consistent UX.
- Threshold'ları named constant + comment olarak yazdım. Tuning
  için tek-yer-değişim, raporda gerekçesi hazır.
- LangChain import edilemiyorsa fallback decorator ekledim
  (`def tool(func): return func`). Standalone test için kritik.
  Container'da langchain yüklü değildi, bu fallback olmasaydı
  test edemezdim.

### Bu deneyimden ne öğrendim?
1. **"Test edilebilir tasarım" en başında düşünülmeli.** `DATA_DIR`
   env var'la override edilebilir, decorator fallback var, helper'lar
   pure function — bunların hepsi "test sırasında ne ihtiyaç var?"
   sorusunun erkenden sorulmasıyla geldi.
2. **Tool docstring'leri prompt engineering'in bir parçası.** Agent
   bu metni okuyarak karar veriyor. "Analyzes logs" gibi muğlak bir
   docstring yerine "Use this tool when the user asks about: [X], [Y],
   [Z]" gibi explicit triggers yazınca routing doğruluğu artar.
   Aslında prompt yazıyoruz, sadece kod yorumu değil.
3. **Threshold'ların dokümantasyonu sayıdan daha önemli.** "5" rakamı
   tek başına anlamsız. "5 — sample data baseline'da en büyük normal
   flow 4 farklı port; 5 distinct port = anomaly threshold" bilgisi
   raporda doğrudan kullanılabilir argüman.
4. **Sample veri + tool eş zamanlı yazılınca çok hızlı oluyor.**
   Önce sample'ı tasarlayıp sonra tool'u yazmak doğru sıraydı:
   tool'u yazarken aklımda hangi event hangi finding'i tetikleyecek
   netti. Test sırasında sayılar uyuştu — debug süresi sıfırdı.
5. **AI optimization önerilerine karşı dikkatli olmak.** "Tek
   tool + parametre" daha az kod, evet. Ama agent routing'i daha
   zor hale getiriyor. Optimization metric önemli — kod satırı mı,
   agent doğruluğu mu? Burada 2. kazanır.

---

## Log #5
**Tarih:** 2026-04-23
**Aşama:** test_tools.py — pytest test suite
**Kullanılan AI aracı:** Claude

### Ne yapmaya çalıştım?
`tests/test_tools.py` yazıp log_analyzer'ı kapsamlı şekilde test etmek.
Görev dosyası "test'ler Hafta 3" diyor ama tool yeni yazıldığı sırada
test yazmak çok daha verimli oldu — beklentiler kafamda taze.
Hedef: her detection branch'i test eden, edge case'leri kapsayan,
cross-correlation'ı doğrulayan bir suite.

### Verdiğim prompt (özet):
"pytest ile log_analyzer'ı test et. Her detection branch için en az
bir test, true negative testleri (normal trafiğin alarm üretmemesi),
threshold boundary testleri, edge case'ler (eksik dosya, boş veri),
ve VPC↔auth cross-correlation testleri olsun."

### AI'ın cevabı işe yaradı mı?

**✅ Çalışan kısımlar:**
- pytest fixture pattern'lerini doğru önerdi: `scope="class"` ile
  rapor sadece bir kez generate edilip class içinde paylaşılıyor
  (her test çağrısında tool tekrar çalışmıyor → hızlı).
- `monkeypatch.setattr(log_analyzer, "DATA_DIR", tmp_path)` ile
  edge case testlerinde DATA_DIR'i izole etmek doğru patern.
- Parameterize testler (örn: `_is_internal` için 9 IP) clean ve
  okunabilir.

**❌ Çalışmayan / dikkat ettiğim kısımlar:**
- AI başlangıçta `analyze_cloudtrail_logs("all")` şeklinde direkt
  çağrı yazdı. Ama langchain-core kurulu olduğunda `@tool` decorator
  fonksiyonu `StructuredTool`'a sarıyor — direkt çağrı deprecation
  warning üretiyor. Doğrusu `.invoke({"query": "all"})`. İki
  ortamı da desteklemek için `call()` helper'ı yazdım.
- AI ilk testlerde sadece "var mı / yok mu" kontrolleri yapıyordu
  ("BRUTE_FORCE_CONSOLE_LOGIN in result"). Ama bu yeterli değil —
  6 mı, 7 mi, 8 mi attempt detect edildi? Severity HIGH mi MEDIUM mi?
  Regex ile gerçek değeri çıkarıp assert eden testler ekledim
  (`test_brute_force_severity_high`, `test_total_findings_count`,
  `test_privesc_count_seven`).
- AI ilk turda **true negative** testlerini atladı. Tool'un alarm
  ÜRETMEDIĞINİ test etmek alarm ürettiğini test etmek kadar önemli.
  `test_a4_noise_not_flagged`, `test_normal_users_not_flagged`,
  `test_dev_user_normal_baseline_not_flagged` ekledim.
- AI cross-correlation testlerini benim yönlendirmemden sonra yazdı.
  Bu testler özel: tek bir tool'u değil **iki tool'un birlikte
  doğru çalışmasını** doğruluyor (aynı IP iki rapora da düşmeli,
  aynı host hem auth hem VPC findings'inde olmalı). Bu sistem-seviye
  test, raporun "multi-source detection" iddiasını kanıtlıyor.

### Hatayı nasıl tespit ettim?
- `pytest -v` çalıştırdım. **53 test ilk çalıştırmada geçti** (0.88s).
- Bu sürpriz değildi, sebep: sample veri + tool aynı zamanda
  tasarlandı, beklentiler kod yorumlarında zaten yazılı. Test'ler
  "kod gerçekten bu beklentilere uyuyor mu?"yu doğruladı, hepsi
  doğru çıktı.
- Tek bir false-pozitif testi: `test_internal_ssh_not_flagged` ilk
  yazdığımda yanlış prefix kontrol yapıyordu. Sample'da DATA_EXFILTRATION
  bulgularındaki "internal" kelimesini "internal SSH var" diye
  yorumladı. Düzelttim: spesifik olarak SSH_BRUTE_FORCE_NETWORK
  bulgusunda iç IP kaynağı OLMAMASINI assert ediyor şimdi.
  (Bu hata test'i çalıştırmadan önce gözle yakalandı, gerçek bir
  failure değil — ama ilkesel olarak iyi bir öğretici an.)

### Nasıl düzelttim?
- `call()` helper'ı: hem LangChain'li hem fallback ortamda çalışan
  invoke pattern.
- Regex-bazlı assert'ler: just-substring değil, **doğru sayı, doğru
  severity, doğru actor** kontrol edildi.
- Section organization: 8 ayrı `Test*` class. Her class farklı
  yönü test ediyor → fail durumunda hangi bölgenin bozulduğu net.
- Edge case'ler `tmp_path` fixture ile izole — gerçek sample'a
  etki etmeden test JSON'ları oluşturup tool'u onlara yöneltiyor.
- Cross-correlation testlerini ayrı class'a koydum
  (`TestCrossCorrelation`). Bunlar **architectural assertions** —
  sistemin parçaları birbiriyle uyumlu çalışıyor mu.

### Bu deneyimden ne öğrendim?
1. **"İlk denemede 53/53" tesadüf değil.** Sample veri tasarlanırken
   her event'in hangi finding'i tetikleyeceği kod yorumlarına
   yazılmıştı. Tool yazılırken aynı belgelenmiş beklentilere uydu.
   Test'ler de aynı beklentileri assert ediyor. Üç katmanın da
   tutarlı olması = ilk denemede yeşil. Documentation-driven
   development gibi bir şey çıktı.
2. **True negative testleri true positive kadar değerli.** "Tool
   şunu yakaladı" testleri her zaman yazılır. "Tool ŞUNU yakalamadı
   — yakalamamalıydı zaten" testleri çoğu zaman atlanır. Halbuki
   false positive oranı detection sisteminin ana kalite metriği.
   Sample data'daki S5 normal trafic, A4 internet noise, dev-user
   morning baseline — hepsi test ile garanti altında.
3. **Cross-correlation test = sistem-seviye assertion.** Tek
   tool'ları test etmek bir adım, tool'ların **birlikte** doğru
   davrandığını test etmek başka bir adım. Bizim ana iddiamız
   "agent multi-source incident'leri görür". Bunu kod seviyesinde
   garanti eden tek şey bu testler.
4. **Test edebilirlik mimarinin kalitesini gösterir.** Tool'u
   yazarken bunlara dikkat ettiğim için (env var override,
   pure helpers, structured returns) test yazmak yarım saatlik
   iş oldu. Eğer DATA_DIR hardcoded olsaydı, eğer findings
   formatlanmadan döndürülseydi, test yazmak saatler sürerdi.
5. **Demo öncesi en güvendiğim doğrulama: pytest yeşil.** Hocaya
   sunarken tool çıktısı beklenmedik bir şekilde değişir mi?
   Hayır — 53 testin biri bile düşerse fark edeceğim. CI'da
   bu testler her commit'te koşacak (Yunus Github Actions kuracak).

---

## Log #6
**Tarih:** 2026-04-29
**Aşama:** PR #9 CI lint hataları — beş tur düzeltme
**Kullanılan AI aracı:** Claude (kodu yazan), GitHub Actions ruff (yakalayan)

### Ne yapmaya çalıştım?
Hafta 1 closeout PR'ını (log_analyzer + ip_reputation + test_tools)
dev branch'e merge için hazırlamak. Lokal'de tüm testler geçiyordu,
"basit bir PR" diye düşündüm. Gerçek hayat farklı çıktı: CI ruff
check 5 ayrı turda fail etti. Her tur farklı kategori hata.

### Verdiğim prompt'lar (özet):
"Lint hatasını düzelt" — sonra her turda yeni hata mesajı paylaştım,
Claude düzeltti, push'ladım, CI yine fail etti.

### AI'ın cevabı işe yaradı mı?

**Tur 1: E701 — multiple statements on one line**
Claude `_format_section_abuseipdb`'de tek satır `if cond: out += ...`
formatı kullanmıştı. Compact ve okunaklı diye yazmış. PEP 8 ihlali.
Düzeltme: her if'i ayrı satıra böldüm. Aynı zamanda `is_private` bug'ı
yakaladım (RFC 5737 doc range'leri yanlış internal classify ediyordu).

**Tur 2: E741 — ambiguous variable name 'l'**
Claude analyze_auth_logs'ta loop variable olarak `l` kullanmıştı —
12 yerde. PEP 8: küçük L harfi 1 ve büyük I ile karıştırılır,
single-char identifier olarak yasak. Düzeltme: hepsini `entry`
ile değiştirdim.

**Tur 3 + 4 + 5: W292/W293 — trailing newline ve whitespace**
Bunlar bana ait hatalar. İlk düzeltmemde dosyalar editor'um
(Notepad gibi sade) trailing newline eklemedi. İkinci turda
elle Enter bastığımda bazı satırlarda whitespace kaldı (auto-indent
kalıntısı). Çözüm: `ruff check --fix` otomatik halletti, sonra
GitHub web editor'unda da temizledim — daha temiz tutuyor.

### Hatayı nasıl tespit ettim?
- Lokal pytest 53/53 geçiyordu, hiç şüphem yoktu
- CI Yunus'un ruff workflow'u her tur açıkça gösterdi: hangi dosya,
  hangi satır, hangi kural. Hata mesajları ucu açık değildi.
- Her tur Claude ile çözdüm, bir sonraki turda yeni kategori çıktı

### Nasıl düzelttim?
- Sistematik: hata mesajını al → Claude'a göster → fix uygula → push → CI bekle → tekrar
- Sonunda bir refleks oluştu: Claude'un kodunu kabul etmeden önce
  "burada lint kuralı ihlali var mı?" diye gözden geçirme
- `ruff check --fix` lokal kullanmayı öğrendim — push'tan önce
  her şeyi yakalıyor

### Bu deneyimden ne öğrendim?
1. **AI estetik tercihleri standartlardan üstün tutmaz.** Tek satır
   inline if Claude'a okunaklı geldi, PEP 8 yasakladı. Style guide
   her zaman kişisel tercihten önce gelir — ekipler bu ortak kuralda
   anlaşır.
2. **CI hata mesajları paha biçilmez geri bildirim.** Lokal'de yıllarca
   görmediğin bug'ları CI 30 saniyede yakalar. Yunus'un ruff
   workflow'u olmasaydı bu kod kalitesizdi ama "çalışıyordu".
3. **`l` değişken adı klasik AI hatası.** Eğitim verisinde sıkça
   geçen pattern, AI öğrenmiş, ama PEP 8 zaman içinde bunu yasaklamış.
   AI'ın training data'sı = best practice değil.
4. **Ruff'un --fix flag'i hayat kurtarır.** Manual düzeltmek hata
   yapma olasılığı yüksek (ben de whitespace bıraktım). Otomatik fix
   güvenli alanı genişletiyor.
5. **Push etmeden önce daima `ruff check --fix` + `pytest` çalıştır.**
   Bu artık benim local hook'um. Gerçi pre-commit hook ekleyebilirdim
   ama o kadar zaman yok — manuel disiplin yeterli.

---

## Log #7
**Tarih:** 2026-04-29
**Aşama:** Lokal'de geçen test'ler CI'da ImportError ile çöktü
**Kullanılan AI aracı:** Claude

### Ne yapmaya çalıştım?
Lint hatalarını çözdükten sonra CI bu sefer pytest aşamasında
çöktü: `ModuleNotFoundError: No module named 'log_analyzer'`.
Halbuki lokal'de 53/53 sorunsuz geçiyordu. Anlamsızdı —
ta ki dizin yapısını fark edene kadar.

### Verdiğim prompt:
"CI'da ImportError aldı, lokal'de geçiyordu. Logu paylaşıyorum,
sebep ne olabilir?"

### AI'ın cevabı işe yaradı mı?

**✅ Çalışan kısım:** Claude doğru teşhis koydu — `sys.path` test
dosyasının dizinine işaret ediyordu, `log_analyzer.py` ise farklı
dizinde. Lokal'de yan yana duruyorlardı, CI'da değil.

**❌ Bende olan eksik:** Test dosyamı yazarken sample data yan yana
çalıştırıyordum (development convenience). "Production layout'ta da
çalışsın mı?" diye düşünmedim. Asıl repo yapısı:
```
backend/
  app/agent/tools/log_analyzer.py
  data/sample_logs/*.json
  tests/test_tools.py
```
Test'ten log_analyzer'a ulaşmak için `_TOOLS_DIR` hesaplamak lazım.

### Hatayı nasıl tespit ettim?
- CI hata logu açıktı: `import log_analyzer` satırında ModuleNotFoundError
- Geri kalan iş Claude ile gerçek dizin yapısını lokal'de simule etmekti
- Claude `/tmp` altına `backend/...` ağacı oluşturup CI'ın yaptığı gibi
  `cd backend && pytest tests/` çalıştırdı — aynı hatayı lokal'de
  reproduce etti

### Nasıl düzelttim?
test_tools.py'nin path setup bölümünü yeniden yazdım:

```python
_THIS_DIR    = Path(__file__).resolve().parent          # backend/tests
_BACKEND_DIR = _THIS_DIR.parent                          # backend
_TOOLS_DIR   = _BACKEND_DIR / "app" / "agent" / "tools"
_DATA_DIR    = _BACKEND_DIR / "data" / "sample_logs"

sys.path.insert(0, str(_TOOLS_DIR))
os.environ["CLOUDGUARD_DATA_DIR"] = str(_DATA_DIR)
```

Yorum eklendi: "test bu dosyaya göre relative çalışır, pytest'i
nereden invoke ettiğin önemli değil."

CI simulation lokal'de yapıldı: `cd /tmp/ci_simulation/backend &&
pytest tests/` → 53/53 PASS. Aynı şartlarda CI da yeşil çıktı.

### Bu deneyimden ne öğrendim?
1. **"Benim makinemde çalışıyor" en eski yazılım anti-pattern'i.**
   Lokal yan-yana dosyalar production layout'unu yansıtmıyordu.
   Test dosyası gerçek path'lere göre yazılmalıydı.
2. **`Path(__file__).parent` paterni `sys.path.insert(0, ...)`'ten
   üstün.** Çünkü hangi dizinden çağırırsan çağır, dosyanın kendi
   konumuna göre relative çalışır.
3. **CI environment'ı lokal'de simule etmek değerli.** `/tmp`
   altında repo ağacını oluşturup `cd backend && pytest` çalıştırmak
   30 saniye sürdü, sonsuz "deploy and pray" turlarından kurtardı.
4. **CI bir kalite kapısı, sadece bir test çalıştırıcı değil.**
   "Bu kod farklı bir bilgisayarda da çalışır mı?" sorusunu
   her commit'te soruyor.
5. **Path bağımlılıklarını test etmek pytest'in kendisini test
   etmek demek.** Test'imin path'i bulması = test framework'ün
   düzgün setup'ı = ürünün CI'da koşabilir olması. Üst seviyede
   bir kalite metriği.

---

## Hafta 1 Özeti

**Teslim edilen:**
- 3 sample log dosyası (109 event, 5 senaryo, cross-source correlation)
- log_analyzer.py — 3 @tool fonksiyonu, MITRE ATT&CK mapping, ~580 satır
- ip_reputation.py — AbuseIPDB + VirusTotal entegrasyonu, demo mode
- test_tools.py — 53 pytest test, true negative + cross-correlation testleri

**Toplam AI etkileşimi:** Claude ana, ~7 entry'lik dokümante süreç,
5 CI iterasyon turu (lint hataları + path bug).

**En değerli ders (genel):** AI iyi bir co-pilot ama hâlâ bir co-pilot.
Pilotluk insanın. Kararı veren, kontrolü yapan, hata mesajını okuyan,
"bu doğru mu?" diye soran ben olmalıyım. Claude bana hızlandırıcı,
hatırlatıcı, tartışmacı oldu — ama her seferinde son söz benim.