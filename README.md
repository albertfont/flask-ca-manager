# Local CA Manager (Flask + Docker)

A tiny, self-hosted CA for home labs. Create a CA per internal TLD (e.g., `home`, `local`, `casa`), issue certificates for subdomains, and download the CA cert to trust it in your browser.

> ⚠️ **Security note**: This is for home/lab use. CA private keys are stored unencrypted on disk so services can read them easily. For stronger security, encrypt keys at rest and restrict filesystem/host access.

## Quick start

```bash
git clone https://github.com/albertfont/flask-ca-manager.git
cd flask-ca-manager
docker compose up --build -d
# Open http://localhost:8000
```
```bash
docker exec -it flask-ca-manager flask shell
>>> from app.models import db, User
>>> u = User(username='admin', role='admin'); u.set_password('adminpass'); db.session.add(u); db.session.commit()
```

Llavors entra a `http://localhost:8000/login` amb `admin/adminpass` i crea usuaris o gestiona CA.

Data is persisted under `./data/` on the host.

## How to use

1. **Create a CA**: Provide a name and an internal TLD (e.g., `home`).
2. **Download the CA cert**: Install it in your OS/Browser trust store.
   - macOS Keychain Access → System → Certificates → Import
   - Windows MMC → Certificates (Local Computer) → Trusted Root CAs → Import
   - Firefox: Settings → Privacy & Security → Certificates → View → Authorities → Import
3. **Issue a certificate**: For a subdomain (e.g., `nas.home`). Add SANs if needed.
4. **Download leaf certs**: `bundle` (fullchain), `crt` (leaf only), `key` (private key).
5. **Delete**: Remove unwanted certificates.

## Paths inside container
- DB: `/data/db/app.db`
- CA files: `/data/certs/ca/<tld>/<tld>-ca.(crt|key)`
- Issued: `/data/certs/issued/<tld>/<common_name>/`

## Customization
- Validity: CA 10 years; leaf 825 days (defaults). Change in `app/ca_utils.py`.
- Key sizes: CA 4096, leaf 2048.

## API/Routes
- `GET /` — list all CAs; create a new one; quick links.
- `GET /ca/<id>` — CA detail and issue certs.
- `GET /ca/<id>/download` — download CA certificate (CRT).
- `POST /ca/<id>/issue` — issue new certificate (form fields: `common_name`, `san`, `days_valid`).
- `GET /cert/<id>/download?type=bundle|crt|key` — download artifacts.
- `POST /cert/<id>/delete` — delete a certificate and files.

## Reverse proxy (optional)
If you run behind Caddy/NGINX, ensure it forwards headers correctly. The app is `ProxyFix` aware.

## Backups
Just back up the host `./data/` directory.

## License
MIT
