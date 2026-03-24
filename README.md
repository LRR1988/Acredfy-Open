# Acredfy

**Digital certificate manager for Windows** — switch between FNMT certificates in seconds.

Acredfy allows tax advisors, accountants, and professional firms (*asesorías*, *gestorías*) to quickly activate any of their clients' digital certificates when accessing Spanish government websites (AEAT, Seguridad Social, SEPE, Cl@ve, etc.).

## How it works

1. Select a certificate from the list (search by name, DNI, or company)
2. Paste the government website URL
3. Click "Activar y abrir" — Acredfy writes the browser auto-select policy and opens the site

The browser automatically presents the correct certificate. No manual selection dialogs.

## Features

- **Instant search** — find certificates by name, DNI, organization, or thumbprint (150ms debounce)
- **Visual expiry indicators** — green (valid), yellow (expiring within 30 days), red (expired)
- **Wildcard URL patterns** — covers all government subdomains and Cl@ve authentication gateway
- **Multi-browser support** — Chrome, Edge, and Firefox
- **Bookmarks** — save frequently used government sites for quick access
- **Auto-update** — application and URL patterns update automatically
- **InPrivate/Incognito mode** — clean TLS sessions, no cached certificates

## Requirements

- Windows 10 / Windows 11 (64-bit)
- Python 3.10+ (for development) or the compiled `.exe`
- Google Chrome, Microsoft Edge, or Mozilla Firefox
- FNMT digital certificates installed in the Windows certificate store

## Installation

### From installer (recommended)
Download the latest installer from [acredfy.com](https://acredfy.com).

### From source
```bash
git clone https://github.com/LRR1988/Acredfy-Open.git
cd Acredfy-Open
pip install -r requirements.txt
python Acredfy.pyw
```

## Technical details

Acredfy writes the `AutoSelectCertificateForUrls` policy to the Windows registry:
- `HKCU\SOFTWARE\Policies\Google\Chrome\AutoSelectCertificateForUrls`
- `HKCU\SOFTWARE\Policies\Microsoft\Edge\AutoSelectCertificateForUrls`

A 3-second loading page allows the browser to load policies asynchronously before navigating to the target URL. Edge Startup Boost is disabled via registry to prevent stale policy caching.

## Author

**Luis Requena Rentero**
- Email: requenarenteroluis@gmail.com
- Web: [acredfy.com](https://acredfy.com)
- GitHub: [@LRR1988](https://github.com/LRR1988)

## License

MIT License — see [LICENSE](LICENSE) for details.
