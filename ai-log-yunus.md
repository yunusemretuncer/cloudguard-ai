## Log #X
**Tarih:** 2026-04-24
**Aşama:** Agent core — ilk LLM çağrısı
**Kullanılan AI aracı:** Claude (proje planlaması)

### Ne yapmaya çalıştım?
Agent'a ilk mesajı atıp Gemini'den cevap almak.

### Sorun
Proje şablonu `gemini-2.0-flash` kullanmamı söylüyordu. Kod çalıştı,
API'ye istek gitti ama Google 429 döndü:
"Quota exceeded ... limit: 0, model: gemini-2.0-flash"

Limit 0 — hiç kullanmamıştım ama hakkım yoktu. Önce API key'imde
problem sandım, yeni key oluşturdum, aynı hata.

### Nasıl tespit ettim?
Hata mesajındaki "limit: 0" satırı dikkatimi çekti. Normal quota
aşımında limit pozitif bir sayı olur ve "retry in X minutes" der.
"limit: 0" yapısal bir erişim sorunu demek.

### Nasıl çözdüm?
Gemini free tier dokümantasyonunu kontrol ettim. Öğrendim ki:
`gemini-2.0-flash` Şubat 2026'da deprecate edilmiş, Mart 2026'da
retire olmuş. Proje şablonu bu değişiklikten önce yazılmış.
Güncel free tier modelleri: 2.5-pro, 2.5-flash, 2.5-flash-lite.
Model adını `gemini-2.5-flash`'e çevirdim, çalıştı.

### Bu deneyimden ne öğrendim?
AI tool'larıyla çalışırken dokümantasyon ve modellerin yaşam döngüsü
çok hızlı değişiyor. Proje başlangıcında çalışan bir API 2-3 ay sonra
deprecate olmuş olabilir. Bir proje template'i körü körüne kopyalamak
yerine güncel durumu kontrol etmek şart.