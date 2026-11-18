# NinoMCP Gateway

Server MCP self-hosted dengan fitur setara inti AnythingMCP: mengubah API dan
database yang sudah ada menjadi tool MCP di balik satu endpoint yang
terautentikasi, dibatasi peran (RBAC), dan tercatat di audit log.

Dibangun untuk Keiko, 2026-11-18. Lisensi: pakai bebas untuk keperluan sendiri.

## Fitur

| Fitur AnythingMCP | Di sini |
|---|---|
| REST/OpenAPI → tool MCP tanpa kode | Impor spec OpenAPI (URL atau JSON/YAML), semua operasi jadi tool otomatis |
| GraphQL → tool MCP | Satu tool query per upstream GraphQL |
| Database SQL → tool MCP | Tool SELECT read-only ke SQLite (query tulis ditolak) |
| MCP Bridge | Mengimpor tool dari server MCP remote lain dan meneruskan panggilannya |
| Satu endpoint untuk banyak server | `POST /mcp` (semua) dan `POST /mcp/<slug>` (per server) |
| OAuth 2.0 sign-in | Authorization server sendiri: `/authorize`, `/token` (PKCE S256), `/register` (dynamic client registration), `/revoke`, metadata `/.well-known/*` |
| API key | Key per pengguna (`gw_...`), disimpan sebagai hash SHA-256 |
| Role-based tool access | Peran `admin` / `user`; tiap tool punya `allowed_roles` |
| Audit log | Setiap `tools/call` tercatat: aktor, tool, argumen, status, durasi |
| Dashboard | Kelola server, upstream, tool, user, API key, dan audit log dari browser |
| Marketplace 891 konektor siap pakai | **Tidak** termasuk — ini versi inti; upstream ditambahkan sendiri lewat dashboard/API |

Belum termasuk: adapter SOAP/WSDL, enkripsi kredensial upstream di database
(kredensial upstream saat ini disimpan sebagai JSON biasa di SQLite lokal —
jangan pakai untuk kredensial produksi bernilai tinggi), dan multi-tenancy.

## Menjalankan

```bash
./start.sh
# atau manual:
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

- Dashboard: http://localhost:8000/ — login default **admin / changeme**
  (ganti lewat env `GATEWAY_ADMIN_USER` / `GATEWAY_ADMIN_PASSWORD` sebelum run pertama,
  atau buat user admin baru dari dashboard lalu hapus yang lama dari database).
- Variabel lingkungan:
  - `GATEWAY_PORT` (default 8000), `GATEWAY_HOST` (default 0.0.0.0)
  - `GATEWAY_PUBLIC_BASE` — URL publik server (dipakai di metadata OAuth; wajib benar
    kalau dipasang di balik domain/HTTPS, karena client MCP seperti Muse terhubung dari cloud)
  - `GATEWAY_DB` — lokasi file SQLite (default `data/gateway.db`)
  - `GATEWAY_SECRET` — kunci penandatangan sesi (default: file `data/secret.key`)

## Cara pakai singkat

1. Login ke dashboard, buat **API key** (ditampilkan sekali).
2. Tambahkan upstream:
   - **OpenAPI**: menu Import OpenAPI — isi `spec_url` dan `base_url`.
   - **GraphQL**: type `graphql`, config `{"base_url": "https://.../graphql", "headers": {}}`.
   - **SQL**: type `sql`, config `{"db_path": "/path/file.db"}`.
   - **MCP bridge**: type `mcp`, config `{"base_url": "https://.../mcp", "headers": {"Authorization": "Bearer ..."}}`.
   - **REST manual**: buat upstream type `rest`, lalu `POST /admin/tools` per endpoint.
3. Hubungkan client MCP (Claude, Cursor, Muse custom connector, dll.) ke
   `https://<domain-kamu>/mcp` atau `/mcp/<slug>` dengan header
   `Authorization: Bearer <API key>` — atau lewat OAuth: client membaca
   `/.well-known/oauth-protected-resource`, mendaftar di `/register`, lalu
   sign-in di `/authorize`.

## Pengujian

```bash
.venv/bin/python demo_upstream.py &   # API demo di :9001
.venv/bin/python app.py &             # gateway di :8000, database baru
.venv/bin/python test_e2e.py          # 24 pemeriksaan end-to-end
```

Hasil uji 2026-11-18: **24/24 lulus** — health, login, API key, impor OpenAPI,
GraphQL, SQL (termasuk penolakan DELETE), initialize/list/call MCP, 401 tanpa
auth, RBAC (sembunyikan + blokir tool admin), MCP bridge (impor + proxy call),
alur OAuth lengkap dengan PKCE, metadata well-known, dan audit log.

## Struktur

- `app.py` — seluruh gateway (protokol MCP, OAuth, admin API, dashboard)
- `demo_upstream.py` — API demo untuk pengujian
- `test_e2e.py` — pengujian end-to-end
- `data/` — database SQLite + kunci rahasia (jangan dibagikan)

## Deploy ke Vercel lewat impor GitHub

1. Di [vercel.com/new](https://vercel.com/new), impor repository ini. Framework
   terdeteksi sebagai FastAPI; entrypoint-nya `app.py` (sudah diatur juga di
   `vercel.json`).
2. Sebelum Deploy, tambahkan Environment Variables berikut (Production + Preview):

   | Key | Value |
   |---|---|
   | `GATEWAY_DATA_DIR` | `/tmp/ninomcp` (filesystem Vercel hanya bisa ditulis di /tmp) |
   | `GATEWAY_SECRET` | string acak panjang buatan sendiri (untuk menandatangani sesi) |
   | `GATEWAY_ADMIN_USER` | `admin` |
   | `GATEWAY_ADMIN_PASSWORD` | kata sandi admin dashboard buatan sendiri |
   | `GATEWAY_PUBLIC_BASE` | URL deployment kamu, mis. `https://ninomcp-gateway.vercel.app` — isi setelah deploy pertama, lalu redeploy sekali agar metadata OAuth benar |

3. Catatan serverless: database SQLite tinggal di /tmp, jadi data (user, API key,
   upstream, audit) **ter-reset saat instance Vercel berganti/cold start**. Cocok
   untuk demo dan uji koneksi MCP; untuk produksi persisten, jalankan di VPS/
   kontainer dengan disk tetap atau ganti storage ke database eksternal.
