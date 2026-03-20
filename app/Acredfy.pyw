#!/usr/bin/env python3
"""
Acredfy — Conmutador rapido de Certificados Digitales
Busca un certificado, click, y el navegador lo usa automaticamente.
Abre cada sesion en ventana InPrivate/Incognito para evitar cache TLS.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import winreg
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timezone

# Allow imports from parent when running as script or frozen exe
if getattr(sys, 'frozen', False):
    _base = sys._MEIPASS
else:
    _base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _base not in sys.path:
    sys.path.insert(0, _base)

from app.config import (
    POLICIES_FILE, SITES_FILE, ACCESSES_FILE, APP_VERSION,
    ensure_data_dir, DATA_DIR,
)
from app.auth import (
    is_licensed, activate as activate_license_key,
    get_license_info, deactivate as deactivate_license,
    LicenseError,
)
from app.updater import (
    check_for_updates, apply_data_updates, version_gt,
    download_installer, launch_installer_and_exit,
)

# Ensure data directory exists and defaults are copied
ensure_data_dir()

REG_PATHS = [
    (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Policies\Google\Chrome\AutoSelectCertificateForUrls'),
    (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Policies\Microsoft\Edge\AutoSelectCertificateForUrls'),
]

STATUS_LABELS = {'valido': 'Válido', 'expirado': 'Expirado', 'por_expirar': 'Por expirar'}

DEFAULT_SITES = [
    'https://[*.]clave.gob.es',
    'https://[*.]redsara.es',
    'https://[*.]fnmt.es',
    'https://[*.]administracion.gob.es',
    'https://[*.]agenciatributaria.gob.es',
    'https://[*.]agenciatributaria.es',
    'https://[*.]seg-social.gob.es',
    'https://[*.]seg-social.es',
    'https://[*.]sepe.es',
    'https://[*.]sepe.gob.es',
    'https://[*.]boe.es',
    'https://[*.]sedecatastro.gob.es',
    'https://[*.]hacienda.gob.es',
    'https://[*.]dgt.gob.es',
    'https://[*.]mjusticia.gob.es',
    'https://[*.]justicia.es',
    'https://[*.]face.gob.es',
    'https://[*.]carpetaciudadana.gob.es',
    'https://[*.]registradores.org',
    'https://[*.]inclusion.gob.es',
    'https://[*.]juntadeandalucia.es',
    'https://[*.]dipujaen.es',
    'https://[*.]cica.es',
    'https://[*.]gencat.cat',
    'https://[*.]comunidad.madrid',
    'https://[*.]gva.es',
    'https://[*.]euskadi.eus',
    'https://[*.]xunta.gal',
    'https://[*.]jcyl.es',
    'https://[*.]carm.es',
    'https://[*.]juntaex.es',
    'https://[*.]gobiernodecanarias.org',
]

BROWSERS = {}


# ══════════════════════════════════════════════════════════════
#  Backend
# ══════════════════════════════════════════════════════════════

def detect_browsers():
    paths = {
        'Edge': [
            os.path.expandvars(r'%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe'),
            os.path.expandvars(r'%ProgramFiles%\Microsoft\Edge\Application\msedge.exe'),
        ],
        'Chrome': [
            os.path.expandvars(r'%ProgramFiles%\Google\Chrome\Application\chrome.exe'),
            os.path.expandvars(r'%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe'),
            os.path.expandvars(r'%LocalAppData%\Google\Chrome\Application\chrome.exe'),
        ],
        'Firefox': [
            os.path.expandvars(r'%ProgramFiles%\Mozilla Firefox\firefox.exe'),
            os.path.expandvars(r'%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe'),
        ],
    }
    exe_names = {'Edge': 'msedge', 'Chrome': 'chrome', 'Firefox': 'firefox'}
    found = {}
    for name, candidates in paths.items():
        for p in candidates:
            if os.path.isfile(p):
                found[name] = p
                break
        else:
            exe = shutil.which(exe_names.get(name, name.lower()))
            if exe:
                found[name] = exe
    return found


def get_certificates_from_store():
    ps_script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Get-ChildItem cert:\CurrentUser\My | ForEach-Object {
    [PSCustomObject]@{
        Thumbprint         = $_.Thumbprint
        Subject            = $_.Subject
        Issuer             = $_.Issuer
        FriendlyName       = $_.FriendlyName
        NotBefore          = $_.NotBefore.ToString('o')
        NotAfter           = $_.NotAfter.ToString('o')
        HasPrivateKey      = $_.HasPrivateKey
        SerialNumber       = $_.SerialNumber
        EnhancedKeyUsage   = ($_.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ', '
        SignatureAlgorithm = $_.SignatureAlgorithm.FriendlyName
    }
} | ConvertTo-Json -Depth 3
"""
    result = subprocess.run(
        ['powershell', '-NoProfile', '-Command', ps_script],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    if result.returncode != 0:
        raise RuntimeError(f"PowerShell error: {result.stderr.strip()}")

    output = result.stdout.strip()
    if not output:
        return []

    raw_certs = json.loads(output)
    if isinstance(raw_certs, dict):
        raw_certs = [raw_certs]

    return [enrich_certificate(c) for c in raw_certs]


def parse_dn(subject):
    result = {}
    parts = re.split(r',\s*(?=\w[\w.]*=)', subject)
    for part in parts:
        part = part.strip()
        eq = part.find('=')
        if eq > 0:
            result[part[:eq].strip()] = part[eq + 1:].strip()
    return result


def enrich_certificate(cert):
    subject = cert.get('Subject', '')
    issuer = cert.get('Issuer', '')
    dn = parse_dn(subject)
    issuer_dn = parse_dn(issuer)

    tipo = 'Personal'
    organization = ''
    display_name = ''
    dni = ''
    cn = dn.get('CN', '')

    if re.search(r'\(R\s*:', cn):
        tipo = 'Representacion'
        organization = dn.get('O', '')
        match = re.match(r'(\S+)\s+(.+?)\s*\(R', cn)
        if match:
            dni = match.group(1)
            display_name = match.group(2).strip()
        else:
            display_name = cn
    else:
        serial = dn.get('SERIALNUMBER', '')
        if serial.startswith('IDCES-'):
            dni = serial[6:]
        elif ' - ' in cn:
            parts = cn.rsplit(' - ', 1)
            if len(parts) == 2:
                dni = parts[1].strip()
        if ' - ' in cn:
            display_name = cn.rsplit(' - ', 1)[0].strip()
        else:
            display_name = cn
        given = dn.get('G', '')
        surname = dn.get('SN', '')
        if given and surname:
            display_name = f"{given} {surname}"

    issuer_cn = issuer_dn.get('CN', '')

    status = 'valido'
    try:
        not_after = datetime.fromisoformat(cert.get('NotAfter', ''))
        now = datetime.now(timezone.utc) if not_after.tzinfo else datetime.now()
        if now > not_after:
            status = 'expirado'
        elif (not_after - now).days <= 30:
            status = 'por_expirar'
    except (ValueError, TypeError):
        pass

    cert['display_name'] = display_name
    cert['dni'] = dni
    cert['tipo'] = tipo
    cert['organization'] = organization
    cert['issuer_short'] = issuer_cn or issuer
    cert['status'] = status
    cert['subject_cn'] = cn
    cert['issuer_cn'] = issuer_cn
    return cert


# ── Sites config ──

def load_sites():
    if os.path.exists(SITES_FILE):
        with open(SITES_FILE, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                pass
    save_sites(DEFAULT_SITES)
    return list(DEFAULT_SITES)


def save_sites(sites):
    with open(SITES_FILE, 'w', encoding='utf-8') as f:
        json.dump(sites, f, ensure_ascii=False, indent=2)


# ── Accesos guardados ──

DEFAULT_ACCESSES = [
    {"name": "AEAT - Sede Electrónica", "url": "https://sede.agenciatributaria.gob.es"},
    {"name": "AEAT - Acceso con certificado", "url": "https://www1.agenciatributaria.gob.es/wlpl/OVCT-CXEW/DialogoRepresentacion?ref=%2Fwlpl%2FBUGC-JDIT%2FMdcAcceso"},
    {"name": "Seguridad Social - Sede", "url": "https://sede.seg-social.gob.es"},
    {"name": "DEHu - Notificaciones", "url": "https://dehu.redsara.es"},
    {"name": "SEPE - Sede Electrónica", "url": "https://sede.sepe.gob.es"},
    {"name": "Catastro - Sede Electrónica", "url": "https://www.sedecatastro.gob.es"},
    {"name": "Junta Andalucía - Notifica", "url": "https://ws020.juntadeandalucia.es/snja/CallAuthenticationServlet"},
    {"name": "Registro Mercantil - Registradores", "url": "https://sede.registradores.org/site/mercantil"},
    {"name": "FACe - Factura electrónica", "url": "https://face.gob.es"},
    {"name": "Mi Carpeta Ciudadana", "url": "https://carpetaciudadana.gob.es"},
]


def load_accesses():
    if os.path.exists(ACCESSES_FILE):
        with open(ACCESSES_FILE, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                pass
    save_accesses(DEFAULT_ACCESSES)
    return list(DEFAULT_ACCESSES)


def save_accesses(accesses):
    with open(ACCESSES_FILE, 'w', encoding='utf-8') as f:
        json.dump(accesses, f, ensure_ascii=False, indent=2)


# ── Policy / Registry ──

def _write_policies(rules):
    with open(POLICIES_FILE, 'w', encoding='utf-8') as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)


def _sync_to_registry(rules):
    for hive, subkey in REG_PATHS:
        # Delete and recreate in a single key open to avoid race conditions
        key = winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_ALL_ACCESS)
        # Delete all existing values
        while True:
            try:
                name, _, _ = winreg.EnumValue(key, 0)
                winreg.DeleteValue(key, name)
            except OSError:
                break
        # Write new values
        for i, rule in enumerate(rules, 1):
            value = json.dumps(rule, ensure_ascii=False)
            winreg.SetValueEx(key, str(i), 0, winreg.REG_SZ, value)
        winreg.FlushKey(key)  # Force flush to disk
        winreg.CloseKey(key)


def activate_certificate(cert, sites):
    """Set this certificate as the active one for all configured sites."""
    rules = []
    for site in sites:
        rules.append({
            "pattern": site,
            "filter": {
                "ISSUER": {"CN": cert['issuer_cn']},
                "SUBJECT": {"CN": cert['subject_cn']}
            }
        })
    _write_policies(rules)
    _sync_to_registry(rules)


def clear_active():
    """Remove all auto-select rules."""
    _write_policies([])
    _sync_to_registry([])


def format_date(iso_str):
    if not iso_str:
        return '\u2014'
    try:
        return datetime.fromisoformat(iso_str).strftime('%d/%m/%Y')
    except (ValueError, TypeError):
        return iso_str


def disable_startup_boost():
    """Disable Edge Startup Boost so it doesn't restart in the background."""
    try:
        key = winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            r'SOFTWARE\Policies\Microsoft\Edge',
            0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, 'StartupBoostEnabled', 0, winreg.REG_DWORD, 0)
        winreg.FlushKey(key)
        winreg.CloseKey(key)
    except Exception:
        pass


def kill_all_browser(browser_path):
    """Kill ALL instances of the browser, twice to catch Startup Boost restarts."""
    import time
    exe_name = os.path.basename(browser_path)
    for _ in range(2):
        try:
            subprocess.run(
                ['taskkill', '/f', '/im', exe_name],
                capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=5
            )
        except Exception:
            pass
        time.sleep(1)


REDIRECT_PAGE = os.path.join(tempfile.gettempdir(), 'acredfy_loading.html')


ACREDFY_PROFILE = os.path.join(tempfile.gettempdir(), 'acredfy_profile')


def open_fresh(browser_path, url):
    """Open URL in an isolated browser instance using a separate profile.
    Uses --user-data-dir so it doesn't kill existing browser windows.
    The separate profile reads fresh policies from the registry."""
    import base64
    url_b64 = base64.b64encode(url.encode('utf-8')).decode('ascii')

    with open(REDIRECT_PAGE, 'w', encoding='utf-8') as f:
        f.write(f'''<!DOCTYPE html><html><head><meta charset="utf-8">
<style>*{{margin:0}}body{{font-family:Segoe UI,sans-serif;display:flex;justify-content:center;
align-items:center;height:100vh;background:#1e1e2e;color:#cdd6f4}}
.c{{text-align:center}}h2{{color:#89b4fa;margin-bottom:12px}}
p{{color:#a6adc8;font-size:14px}}.dot{{animation:blink 1s infinite}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:0}}}}</style></head>
<body><div class="c"><h2>Acredfy</h2>
<p>Preparando certificado<span class="dot">...</span></p></div>
<script>setTimeout(function(){{location.replace(atob("{url_b64}"));}},3000);</script>
</body></html>''')

    name = os.path.basename(browser_path).lower()
    if 'firefox' in name:
        subprocess.Popen(
            [browser_path, '-private-window', REDIRECT_PAGE],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return
    flag = '--inprivate' if 'edge' in name else '--incognito'
    subprocess.Popen(
        [browser_path, flag, '--new-window', '--no-first-run',
         '--no-default-browser-check',
         '--disable-features=msStartupBoost',
         f'--user-data-dir={ACREDFY_PROFILE}',
         REDIRECT_PAGE],
        creationflags=subprocess.CREATE_NO_WINDOW
    )


# ══════════════════════════════════════════════════════════════
#  Theme & GUI
# ══════════════════════════════════════════════════════════════

# Color palette
C = {
    'bg':       '#f0f2f5',
    'surface':  '#ffffff',
    'primary':  '#2563eb',
    'primary_h':'#1d4ed8',
    'text':     '#1e293b',
    'text2':    '#64748b',
    'border':   '#e2e8f0',
    'green':    '#16a34a',
    'red':      '#dc2626',
    'amber':    '#d97706',
    'row_alt':  '#f8fafc',
    'sel':      '#dbeafe',
    'sel_fg':   '#1e40af',
}


def apply_theme(root):
    style = ttk.Style(root)
    style.theme_use('clam')

    # General
    style.configure('.', font=('Segoe UI', 10), background=C['bg'],
                    foreground=C['text'], borderwidth=0)
    style.configure('TFrame', background=C['bg'])
    style.configure('TLabel', background=C['bg'], foreground=C['text'])
    style.configure('TRadiobutton', background=C['bg'], foreground=C['text'],
                    focuscolor=C['bg'])
    style.map('TRadiobutton',
              background=[('active', C['bg'])],
              foreground=[('selected', C['primary'])])

    # Entries
    style.configure('TEntry', fieldbackground=C['surface'], bordercolor=C['border'],
                    lightcolor=C['surface'], darkcolor=C['surface'],
                    padding=(8, 6))
    style.map('TEntry', bordercolor=[('focus', C['primary'])])

    # Combobox
    style.configure('TCombobox', fieldbackground=C['surface'], bordercolor=C['border'],
                    padding=(8, 6), arrowsize=14)
    style.map('TCombobox', bordercolor=[('focus', C['primary'])])

    # Fix Combobox dropdown listbox styling (prevents cut-off on clam theme)
    root.option_add('*TCombobox*Listbox.font', ('Segoe UI', 10))
    root.option_add('*TCombobox*Listbox.background', C['surface'])
    root.option_add('*TCombobox*Listbox.foreground', C['text'])
    root.option_add('*TCombobox*Listbox.selectBackground', C['sel'])
    root.option_add('*TCombobox*Listbox.selectForeground', C['sel_fg'])

    # Buttons
    style.configure('TButton', background=C['surface'], foreground=C['text'],
                    bordercolor=C['border'], padding=(14, 7), font=('Segoe UI', 10))
    style.map('TButton',
              background=[('active', C['border']), ('pressed', C['border'])],
              bordercolor=[('active', C['border'])])

    style.configure('Primary.TButton', background=C['primary'], foreground='#ffffff',
                    bordercolor=C['primary'], padding=(16, 8), font=('Segoe UI', 10, 'bold'))
    style.map('Primary.TButton',
              background=[('active', C['primary_h']), ('pressed', C['primary_h'])],
              bordercolor=[('active', C['primary_h'])])

    style.configure('Danger.TButton', background=C['surface'], foreground=C['red'],
                    bordercolor=C['border'], padding=(14, 7))
    style.map('Danger.TButton',
              background=[('active', '#fef2f2')],
              foreground=[('active', C['red'])])

    # Treeview
    style.configure('Treeview', background=C['surface'], foreground=C['text'],
                    fieldbackground=C['surface'], bordercolor=C['border'],
                    rowheight=30, font=('Segoe UI', 10))
    style.configure('Treeview.Heading', background='#f1f5f9', foreground=C['text'],
                    font=('Segoe UI', 10, 'bold'), bordercolor=C['border'],
                    padding=(8, 6))
    style.map('Treeview',
              background=[('selected', C['sel'])],
              foreground=[('selected', C['sel_fg'])])

    # Scrollbar
    style.configure('TScrollbar', background=C['border'], troughcolor=C['surface'],
                    bordercolor=C['surface'], arrowsize=14)

    # Separator
    style.configure('TSeparator', background=C['border'])

    # Label variants
    style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), foreground=C['text'])
    style.configure('Subtitle.TLabel', font=('Segoe UI', 10), foreground=C['text2'])
    style.configure('Counter.TLabel', font=('Segoe UI', 9), foreground=C['text2'])
    style.configure('Active.TLabel', font=('Segoe UI', 9, 'bold'), foreground=C['green'])
    style.configure('Status.TLabel', font=('Segoe UI', 9))
    style.configure('StatusOk.TLabel', font=('Segoe UI', 9), foreground=C['green'])
    style.configure('StatusErr.TLabel', font=('Segoe UI', 9), foreground=C['red'])
    style.configure('StatusMuted.TLabel', font=('Segoe UI', 9), foreground=C['text2'])
    style.configure('Search.TLabel', font=('Segoe UI', 10), foreground=C['text2'])
    style.configure('Section.TLabel', font=('Segoe UI', 9, 'bold'), foreground=C['text2'])

    root.configure(bg=C['bg'])


class AcredfyApp(tk.Tk):

    def __init__(self, startup_url=None):
        super().__init__()
        self.title('Acredfy')
        self.geometry('1020x660')
        self.minsize(850, 500)
        self._startup_url = startup_url

        apply_theme(self)

        self.all_certs = []
        self._search_after_id = None
        self.sites = load_sites()
        self.accesses = load_accesses()
        self._prefs_file = os.path.join(DATA_DIR, 'preferences.json')
        self._load_preferences()

        global BROWSERS
        BROWSERS = detect_browsers()

        # Variables
        self.search_var = tk.StringVar()
        self.tipo_var = tk.StringVar(value='all')
        self.status_var = tk.StringVar(value='all')
        self.browser_var = tk.StringVar(value=list(BROWSERS.keys())[0] if BROWSERS else '')
        self.url_var = tk.StringVar()

        self.search_var.trace_add('write', self._on_search_changed)
        self.tipo_var.trace_add('write', lambda *_: self._apply_filters())
        self.status_var.trace_add('write', lambda *_: self._apply_filters())

        self._build_ui()
        self._center_window()
        self._load_certificates()
        self.bind('<F5>', lambda _: self._load_certificates())
        self.after(2000, self._check_for_updates)

        # Apply startup URL if launched via acredfy:// protocol
        if self._startup_url:
            self.url_var.set(self._startup_url)
            self.access_var.set('')

    def _center_window(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f'+{x}+{y}')

    # ── Build UI ──

    def _build_ui(self):
        pad = 16

        # Header
        header = ttk.Frame(self)
        header.pack(fill=tk.X, padx=pad, pady=(pad, 8))
        ttk.Label(header, text='Acredfy', style='Title.TLabel').pack(side=tk.LEFT)
        ttk.Label(header, text=f'v{APP_VERSION}',
                  style='Subtitle.TLabel').pack(side=tk.LEFT, padx=(8, 0), pady=(6, 0))
        license_info = get_license_info()
        if license_info:
            company = license_info.get('company', '')
            if company:
                ttk.Label(header, text=f'({company})',
                          style='Subtitle.TLabel').pack(side=tk.LEFT, padx=(8, 0), pady=(6, 0))
        self.support_btn = ttk.Button(header, text='Soporte', command=self._open_support)
        self.support_btn.pack(side=tk.RIGHT, padx=(0, 6))
        ttk.Button(header, text='Actualizar (F5)', command=self._load_certificates).pack(side=tk.RIGHT)

        # Check for unread ticket replies periodically
        self._check_unread_tickets()

        # Update notification bar (initially hidden)
        self._update_container = ttk.Frame(self)
        self._update_container.pack(fill=tk.X, padx=pad, pady=0)

        # Search bar
        search_frame = ttk.Frame(self)
        search_frame.pack(fill=tk.X, padx=pad, pady=(0, 6))
        ttk.Label(search_frame, text='Buscar:', style='Search.TLabel').pack(side=tk.LEFT, padx=(0, 8))
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var,
                                       font=('Segoe UI', 12))
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.focus_set()

        # Filters
        filters = ttk.Frame(self)
        filters.pack(fill=tk.X, padx=pad, pady=(0, 4))

        ttk.Label(filters, text='Tipo:', style='Section.TLabel').pack(side=tk.LEFT, padx=(0, 6))
        for text, val in [('Todos', 'all'), ('Personal', 'Personal'), ('Repres.', 'Representacion')]:
            ttk.Radiobutton(filters, text=text, variable=self.tipo_var, value=val).pack(side=tk.LEFT, padx=3)

        ttk.Separator(filters, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=12)

        ttk.Label(filters, text='Estado:', style='Section.TLabel').pack(side=tk.LEFT, padx=(0, 6))
        for text, val in [('Todos', 'all'), ('Válido', 'valido'), ('Expirado', 'expirado'), ('Por exp.', 'por_expirar')]:
            ttk.Radiobutton(filters, text=text, variable=self.status_var, value=val).pack(side=tk.LEFT, padx=3)

        # Counter + active cert
        info_bar = ttk.Frame(self)
        info_bar.pack(fill=tk.X, padx=pad, pady=(0, 4))
        self.counter_label = ttk.Label(info_bar, text='', style='Counter.TLabel')
        self.counter_label.pack(side=tk.LEFT)
        self.active_label = ttk.Label(info_bar, text='', style='Active.TLabel')
        self.active_label.pack(side=tk.RIGHT)

        # Loading frame with label + progress bar
        self._loading_frame = ttk.Frame(self)
        self.loading_label = ttk.Label(self._loading_frame, text='Cargando certificados...',
                                        font=('Segoe UI', 11), foreground=C['text2'])
        self.loading_label.pack(pady=(30, 8))
        self._progress_bar = ttk.Progressbar(self._loading_frame, mode='indeterminate', length=300)
        self._progress_bar.pack()
        self._loading_frame.pack(pady=10)

        # Certificate list
        tree_frame = ttk.Frame(self)

        columns = ('nombre', 'dni', 'organizacion', 'tipo', 'estado', 'caduca')
        self.cert_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', selectmode='browse')

        self.cert_tree.heading('nombre', text='Nombre')
        self.cert_tree.heading('dni', text='NIF')
        self.cert_tree.heading('organizacion', text='Organización')
        self.cert_tree.heading('tipo', text='Tipo')
        self.cert_tree.heading('estado', text='Estado')
        self.cert_tree.heading('caduca', text='Caduca')

        for col in columns:
            self.cert_tree.heading(col, command=lambda c=col: self._sort_column(c))

        self.cert_tree.column('nombre', width=190, minwidth=120)
        self.cert_tree.column('dni', width=105, minwidth=80)
        self.cert_tree.column('organizacion', width=260, minwidth=100)
        self.cert_tree.column('tipo', width=105, minwidth=70)
        self.cert_tree.column('estado', width=85, minwidth=60)
        self.cert_tree.column('caduca', width=90, minwidth=65)

        self.cert_tree.tag_configure('valido', foreground=C['green'])
        self.cert_tree.tag_configure('expirado', foreground=C['red'])
        self.cert_tree.tag_configure('por_expirar', foreground=C['amber'])
        self.cert_tree.tag_configure('active', background='#dbeafe', foreground='#1e40af')

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.cert_tree.yview)
        self.cert_tree.configure(yscrollcommand=scrollbar.set)
        self.cert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._cert_tree_frame = tree_frame

        self.cert_tree.bind('<Double-1>', lambda _: self._activate_and_open())
        self.cert_tree.bind('<Button-3>', self._on_cert_right_click)

        # ── Bottom panel ──
        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, side=tk.BOTTOM, padx=pad, pady=(0, pad))

        # Row 0: Favorite quick access buttons
        self._favorites_frame = ttk.Frame(bottom)
        self._favorites_frame.pack(fill=tk.X, pady=(0, 6))
        self._build_favorites()

        # Row 1: Access selector (on top so dropdown has room to open downward)
        row1 = ttk.Frame(bottom)
        row1.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(row1, text='Acceso:', style='Section.TLabel').pack(side=tk.LEFT, padx=(0, 6))
        self.access_var = tk.StringVar()
        self.access_var.trace_add('write', self._on_access_typed)
        self.access_combo = ttk.Combobox(row1, textvariable=self.access_var,
                                          font=('Segoe UI', 10), height=20)
        self.access_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self._refresh_access_combo()
        self.access_combo.bind('<<ComboboxSelected>>', self._on_access_selected)

        ttk.Button(row1, text='Gestionar accesos', command=self._manage_accesses).pack(side=tk.LEFT)

        # Row 2: URL + nav + buttons
        row2 = ttk.Frame(bottom)
        row2.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(row2, text='URL:', style='Section.TLabel').pack(side=tk.LEFT, padx=(0, 6))
        self.url_entry = ttk.Entry(row2, textvariable=self.url_var, font=('Segoe UI', 10))
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        ttk.Label(row2, text='Nav:', style='Section.TLabel').pack(side=tk.LEFT, padx=(0, 4))
        browser_combo = ttk.Combobox(row2, textvariable=self.browser_var,
                                      values=list(BROWSERS.keys()), width=7, state='readonly')
        browser_combo.pack(side=tk.LEFT, padx=(0, 10))

        # Restore last used browser
        if self._prefs.get('browser') and self._prefs['browser'] in BROWSERS:
            self.browser_var.set(self._prefs['browser'])

        self.activate_btn = ttk.Button(row2, text='Activar y abrir',
                                        style='Primary.TButton',
                                        command=self._activate_and_open)
        self.activate_btn.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(row2, text='Desactivar', style='Danger.TButton',
                   command=self._deactivate).pack(side=tk.LEFT)

        # Status line
        self.status_label = ttk.Label(bottom, text='', style='Status.TLabel', wraplength=950)
        self.status_label.pack(fill=tk.X, pady=(4, 0))

        # Help hint
        ttk.Label(bottom,
                  text='Si no encuentras el acceso que buscas o el enlace no funciona, contacta con Soporte.',
                  font=('Segoe UI', 8), foreground=C['text2']).pack(fill=tk.X, pady=(4, 0))

    # ── Certificate loading ──

    def _load_certificates(self):
        self._loading_frame.pack(pady=10)
        self._progress_bar.start(15)
        self._cert_tree_frame.pack_forget()
        self.counter_label.config(text='')

        thread = threading.Thread(target=self._load_certs_thread, daemon=True)
        thread.start()

    def _load_certs_thread(self):
        try:
            certs = get_certificates_from_store()
            self.after(0, self._on_certs_loaded, certs, None)
        except Exception as e:
            self.after(0, self._on_certs_loaded, [], str(e))

    def _on_certs_loaded(self, certs, error):
        self._progress_bar.stop()
        self._loading_frame.pack_forget()
        self._cert_tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 4))

        if error:
            messagebox.showerror('Error', f'No se pudieron cargar los certificados:\n\n{error}')
            return

        self.all_certs = certs
        self._apply_filters()
        self._update_active_label()
        self._check_expiring_certs()

    # ── Search & Filter ──

    def _on_search_changed(self, *_):
        if self._search_after_id:
            self.after_cancel(self._search_after_id)
        self._search_after_id = self.after(150, self._apply_filters)

    def _apply_filters(self):
        search = self.search_var.get().strip().lower()
        tipo = self.tipo_var.get()
        status = self.status_var.get()

        filtered = []
        for cert in self.all_certs:
            if tipo != 'all' and cert.get('tipo') != tipo:
                continue
            if status != 'all' and cert.get('status') != status:
                continue
            if search:
                haystack = ' '.join(filter(None, [
                    cert.get('display_name'), cert.get('dni'),
                    cert.get('issuer_short'), cert.get('organization'),
                    cert.get('SerialNumber'), cert.get('Thumbprint'),
                    cert.get('Subject'), cert.get('FriendlyName')
                ])).lower()
                if not all(term in haystack for term in search.split()):
                    continue
            filtered.append(cert)

        self._populate_tree(filtered)
        self.counter_label.config(text=f'{len(filtered)} de {len(self.all_certs)} certificados')

    def _populate_tree(self, certs):
        self.cert_tree.delete(*self.cert_tree.get_children())
        for cert in certs:
            status = cert.get('status', '')
            self.cert_tree.insert('', tk.END,
                                 iid=cert.get('Thumbprint', ''),
                                 values=(
                                     cert.get('display_name', ''),
                                     cert.get('dni', ''),
                                     cert.get('organization', ''),
                                     cert.get('tipo', ''),
                                     STATUS_LABELS.get(status, status),
                                     format_date(cert.get('NotAfter')),
                                 ),
                                 tags=(status,))

        # Highlight active certificate
        try:
            if os.path.exists(POLICIES_FILE):
                with open(POLICIES_FILE, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                if rules:
                    active_cn = rules[0].get('filter', {}).get('SUBJECT', {}).get('CN', '')
                    for cert in certs:
                        if cert.get('subject_cn') == active_cn:
                            thumbprint = cert.get('Thumbprint', '')
                            if self.cert_tree.exists(thumbprint):
                                self.cert_tree.item(thumbprint, tags=('active',))
                            break
        except Exception:
            pass

    def _sort_column(self, col):
        """Sort treeview by column."""
        items = [(self.cert_tree.set(k, col), k) for k in self.cert_tree.get_children('')]
        # Try numeric sort for dates, otherwise alphabetical
        try:
            items.sort(key=lambda t: t[0])
        except Exception:
            items.sort(key=lambda t: t[0].lower())

        # Toggle sort direction
        if not hasattr(self, '_sort_reverse'):
            self._sort_reverse = {}
        reverse = self._sort_reverse.get(col, False)
        items.sort(key=lambda t: t[0].lower() if isinstance(t[0], str) else t[0], reverse=reverse)
        self._sort_reverse[col] = not reverse

        for index, (val, k) in enumerate(items):
            self.cert_tree.move(k, '', index)

    def _check_expiring_certs(self):
        """Show alert if certificates expire within 7 days."""
        expiring = []
        for cert in self.all_certs:
            if cert.get('status') == 'por_expirar':
                name = cert.get('display_name', '')
                dni = cert.get('dni', '')
                expiry = cert.get('NotAfter', '')[:10] if cert.get('NotAfter') else ''
                expiring.append(f"  - {name} ({dni}) — caduca: {expiry}")

        if expiring:
            msg = f"Los siguientes certificados caducan pronto:\n\n" + "\n".join(expiring)
            messagebox.showwarning('Certificados a punto de caducar', msg)

    # ── Active certificate indicator ──

    def _update_active_label(self):
        if os.path.exists(POLICIES_FILE):
            try:
                with open(POLICIES_FILE, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                if rules:
                    cn = rules[0].get('filter', {}).get('SUBJECT', {}).get('CN', '')
                    self.active_label.config(text=f'Activo: {cn}')
                    return
            except (json.JSONDecodeError, IndexError, KeyError):
                pass
        self.active_label.config(text='')

    # ── Preferences ──

    def _load_preferences(self):
        """Load last used browser and access."""
        self._prefs = {}
        if os.path.isfile(self._prefs_file):
            try:
                with open(self._prefs_file, 'r', encoding='utf-8') as f:
                    self._prefs = json.load(f)
            except Exception:
                pass

    def _save_preferences(self):
        """Save current browser and access selection."""
        self._prefs = {
            'browser': self.browser_var.get(),
            'access': self.access_var.get(),
        }
        try:
            with open(self._prefs_file, 'w', encoding='utf-8') as f:
                json.dump(self._prefs, f)
        except Exception:
            pass

    # ── Right-click context menu ──

    def _on_cert_right_click(self, event):
        """Show context menu on right-click."""
        item = self.cert_tree.identify_row(event.y)
        if not item:
            return
        self.cert_tree.selection_set(item)
        cert = next((c for c in self.all_certs if c.get('Thumbprint') == item), None)
        if not cert:
            return

        menu = tk.Menu(self, tearoff=0)
        nif = cert.get('dni', '')
        if nif:
            menu.add_command(label=f'Copiar NIF: {nif}',
                             command=lambda: self._copy_to_clipboard(nif))
        name = cert.get('display_name', '')
        if name:
            menu.add_command(label=f'Copiar nombre: {name}',
                             command=lambda: self._copy_to_clipboard(name))
        menu.add_separator()
        menu.add_command(label='Activar y abrir', command=self._activate_and_open)
        menu.tk_popup(event.x_root, event.y_root)

    def _copy_to_clipboard(self, text):
        """Copy text to clipboard."""
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_label.config(text=f'Copiado: {text}', style='StatusMuted.TLabel')

    # ── Accesos ──

    def _refresh_access_combo(self):
        self._all_access_names = [a['name'] for a in self.accesses]
        self.access_combo['values'] = self._all_access_names
        if self._all_access_names:
            self.access_combo.current(0)
            self._on_access_selected()
        if hasattr(self, '_prefs') and self._prefs.get('access'):
            last = self._prefs['access']
            if last in self._all_access_names:
                self.access_var.set(last)
                self._on_access_selected()

    def _on_access_typed(self, *_):
        typed = self.access_var.get().strip()
        # Don't filter if empty or if text matches an existing entry exactly
        if not typed or typed in self._all_access_names:
            self.access_combo['values'] = self._all_access_names
            return
        filtered = [n for n in self._all_access_names if typed.lower() in n.lower()]
        self.access_combo['values'] = filtered if filtered else self._all_access_names

    def _on_access_selected(self, event=None):
        selected_name = self.access_var.get()
        acc = next((a for a in self.accesses if a['name'] == selected_name), None)
        if acc:
            self.url_var.set(acc['url'])

    def _build_favorites(self):
        """Build favorite access quick-buttons."""
        for widget in self._favorites_frame.winfo_children():
            widget.destroy()
        favorites = [a for a in self.accesses if a.get('favorite')]
        if not favorites:
            return
        ttk.Label(self._favorites_frame, text='Favoritos:', style='Section.TLabel').pack(side=tk.LEFT, padx=(0, 6))
        for acc in favorites[:6]:
            btn = ttk.Radiobutton(
                self._favorites_frame, text=acc['name'],
                variable=self.url_var, value=acc['url'],
                command=lambda a=acc: self._on_favorite_click(a),
            )
            btn.pack(side=tk.LEFT, padx=3)

    def _on_favorite_click(self, acc):
        self.url_var.set(acc['url'])
        self.access_var.set(acc['name'])

    def _manage_accesses(self):
        AccessesDialog(self)

    # ── Main actions ──

    def _get_selected_cert(self):
        sel = self.cert_tree.selection()
        if not sel:
            messagebox.showinfo('Acredfy', 'Selecciona un certificado de la lista.')
            return None
        return next((c for c in self.all_certs if c.get('Thumbprint') == sel[0]), None)

    def _activate_and_open(self):
        cert = self._get_selected_cert()
        if not cert:
            return

        browser_name = self.browser_var.get()
        if browser_name not in BROWSERS:
            messagebox.showerror('Error', 'No se encontró ningún navegador.')
            return

        url = self.url_var.get().strip()
        if not url:
            messagebox.showinfo('Acredfy', 'Pega la URL de la web a la que quieres acceder.')
            return
        if not url.startswith('http'):
            url = 'https://' + url

        self._save_preferences()

        # Build policy patterns: configured sites + wildcard from the URL domain
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).hostname or ''
            # Extract base domain (e.g., ws020.juntadeandalucia.es → juntadeandalucia.es)
            parts = domain.split('.')
            # Handle multi-part TLDs (.gob.es, .com.es, .org.es, etc.)
            multi_tlds = {'gob', 'com', 'org', 'edu', 'net', 'co'}
            if len(parts) >= 3 and parts[-2] in multi_tlds:
                base_domain = '.'.join(parts[-3:])
            elif len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
            else:
                base_domain = domain
            url_pattern = f'https://[*.]{base_domain}'

            all_patterns = list(set(self.sites + [url_pattern]))

            display = cert.get('organization') or cert.get('display_name', '')
            self.status_label.config(
                text=f'Activando certificado y abriendo navegador...',
                style='StatusMuted.TLabel')
            self.update_idletasks()

            # 1. Disable Startup Boost
            disable_startup_boost()
            # 2. Write policy to registry
            activate_certificate(cert, all_patterns)
            # 3. Open isolated browser instance (separate profile, reads fresh policy)
            open_fresh(BROWSERS[browser_name], url)

            self.status_label.config(
                text=f'Certificado activado: {display} ({cert.get("dni","")}) — '
                     f'Abierto en {browser_name} InPrivate',
                style='StatusOk.TLabel')
            self._update_active_label()
        except Exception as e:
            self.status_label.config(text=f'Error: {e}', style='StatusErr.TLabel')

    def _deactivate(self):
        try:
            clear_active()
            self.status_label.config(text='Certificado desactivado. El navegador volverá a mostrar el diálogo.',
                                     style='StatusMuted.TLabel')
            self._update_active_label()
        except Exception as e:
            self.status_label.config(text=f'Error: {e}', style='StatusErr.TLabel')

    # ── Edit sites ──

    def _refresh_sites(self):
        self.sites = load_sites()

    def _check_unread_tickets(self):
        """Check for unread admin replies every 60 seconds."""
        def do_check():
            try:
                from app.auth import _get_authenticated
                result = _get_authenticated('tickets/unread')
                unread = result.get('unread', 0)
                self.after(0, self._update_support_badge, unread)
            except Exception:
                pass
        threading.Thread(target=do_check, daemon=True).start()
        self.after(60000, self._check_unread_tickets)

    def _update_support_badge(self, unread):
        if unread > 0:
            self.support_btn.config(text=f'Soporte ({unread})')
        else:
            self.support_btn.config(text='Soporte')

    def _open_support(self):
        SupportDialog(self)
        # Refresh badge after closing support dialog
        self.after(500, self._check_unread_tickets)

    def _check_for_updates(self):
        """Check for updates in background on startup."""
        def do_check():
            try:
                result = check_for_updates()
                if result is None:
                    return

                # Apply data updates silently (merge sites/accesos)
                data_result = apply_data_updates(result)

                # Refresh UI if data was updated
                if data_result.get("sites_updated"):
                    self.after(0, self._on_data_updated, "sites")
                if data_result.get("accesos_updated"):
                    self.after(0, self._on_data_updated, "accesos")

                # Check for app version update
                server_version = result.get("app_version", "0.0.0")
                if version_gt(server_version, APP_VERSION):
                    self.after(0, self._show_update_notification, result)
            except Exception:
                pass

        threading.Thread(target=do_check, daemon=True).start()

    def _on_data_updated(self, what):
        """Reload data after silent merge update."""
        if what == "sites":
            self.sites = load_sites()
        elif what == "accesos":
            self.accesses = load_accesses()
            self._refresh_access_combo()

    def _show_update_notification(self, update_info):
        """Show update available bar below header."""
        self._update_info = update_info
        version = update_info.get("app_version", "")

        bar = ttk.Frame(self._update_container)
        bar.pack(fill=tk.X, pady=(4, 0))

        # Use a canvas-based colored background since ttk.Frame bg is theme-controlled
        inner = tk.Frame(bar, bg='#dbeafe', padx=12, pady=8)
        inner.pack(fill=tk.X)

        tk.Label(inner, text=f'Nueva versión {version} disponible',
                 font=('Segoe UI', 10, 'bold'), fg='#1e40af', bg='#dbeafe').pack(side=tk.LEFT)

        tk.Button(inner, text='Actualizar', font=('Segoe UI', 9, 'bold'),
                  fg='#ffffff', bg='#16a34a', relief=tk.FLAT, padx=12, pady=4,
                  cursor='hand2', command=self._start_app_update).pack(side=tk.RIGHT)

        changelog = update_info.get("changelog", "")
        if changelog:
            tk.Label(inner, text=f'  —  {changelog}', font=('Segoe UI', 9),
                     fg='#64748b', bg='#dbeafe').pack(side=tk.LEFT, padx=(8, 0))

        self._update_bar = bar

    def _start_app_update(self):
        """Download new version and launch installer."""
        if not hasattr(self, '_update_info') or not self._update_info:
            return

        download_url = self._update_info.get("download_url", "")
        if not download_url:
            return

        # Change button to progress text
        for widget in self._update_bar.winfo_children():
            widget.destroy()

        inner = tk.Frame(self._update_bar, bg='#dbeafe', padx=12, pady=8)
        inner.pack(fill=tk.X)
        self._download_label = tk.Label(inner, text='Descargando actualización...',
                                         font=('Segoe UI', 10), fg='#1e40af', bg='#dbeafe')
        self._download_label.pack(side=tk.LEFT)

        def do_download():
            try:
                def on_progress(downloaded, total):
                    pct = int(downloaded / total * 100) if total else 0
                    self.after(0, lambda p=pct: self._download_label.config(
                        text=f'Descargando actualización... {p}%'))

                path = download_installer(download_url, on_progress)
                self.after(0, lambda: self._on_download_complete(path))
            except Exception as e:
                self.after(0, lambda: self._download_label.config(
                    text=f'Error al descargar: {e}'))

        threading.Thread(target=do_download, daemon=True).start()

    def _on_download_complete(self, installer_path):
        """Installer downloaded. Launch it and exit."""
        self._download_label.config(
            text='Instalando actualización... La aplicación se cerrará. Vuelve a abrirla cuando termine.')
        self.update_idletasks()
        self.after(1500, lambda: launch_installer_and_exit(installer_path))


class AccessesDialog(tk.Toplevel):

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title('Gestionar accesos')
        self.geometry('700x500')
        self.resizable(True, True)
        self.minsize(600, 450)
        self.transient(parent)
        self.grab_set()

        self._build_ui()

        self.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        py = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f'+{px}+{py}')

        self.bind('<Escape>', lambda _: self.destroy())

    def _build_ui(self):
        ttk.Label(self, text='Accesos guardados (marca favoritos con la estrella):',
                  font=('Segoe UI', 9)).pack(anchor=tk.W, padx=12, pady=(12, 4))

        # List
        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=12)

        columns = ('fav', 'nombre', 'url')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings',
                                  selectmode='browse', height=10)
        self.tree.heading('fav', text='Fav')
        self.tree.heading('nombre', text='Nombre')
        self.tree.heading('url', text='URL')
        self.tree.column('fav', width=40, minwidth=30, anchor=tk.CENTER)
        self.tree.column('nombre', width=180, minwidth=100)
        self.tree.column('url', width=320, minwidth=200)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        for a in self.parent.accesses:
            fav_mark = '*' if a.get('favorite') else ''
            self.tree.insert('', tk.END, values=(fav_mark, a['name'], a['url']))

        # Add form
        add_frame = ttk.Frame(self)
        add_frame.pack(fill=tk.X, padx=12, pady=(8, 4))

        ttk.Label(add_frame, text='Nombre:').grid(row=0, column=0, sticky=tk.W, padx=(0, 4))
        self.name_entry = ttk.Entry(add_frame, width=25)
        self.name_entry.grid(row=0, column=1, sticky=tk.EW, padx=(0, 8))

        ttk.Label(add_frame, text='URL:').grid(row=0, column=2, sticky=tk.W, padx=(0, 4))
        self.url_entry = ttk.Entry(add_frame, width=35)
        self.url_entry.grid(row=0, column=3, sticky=tk.EW)
        self.url_entry.bind('<Return>', lambda _: self._add())

        add_frame.columnconfigure(1, weight=1)
        add_frame.columnconfigure(3, weight=2)

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=12, pady=(4, 12))

        ttk.Button(btn_frame, text='Añadir', command=self._add).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frame, text='Favorito', command=self._toggle_favorite).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frame, text='Eliminar', command=self._remove).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frame, text='Guardar', command=self._save).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(btn_frame, text='Cancelar', command=self.destroy).pack(side=tk.RIGHT)

    def _add(self):
        name = self.name_entry.get().strip()
        url = self.url_entry.get().strip()
        if not name or not url:
            return
        if not url.startswith('http'):
            url = 'https://' + url
        self.tree.insert('', tk.END, values=('', name, url))
        self.name_entry.delete(0, tk.END)
        self.url_entry.delete(0, tk.END)
        self.name_entry.focus_set()

    def _toggle_favorite(self):
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], 'values')
        fav, name, url = values[0], values[1], values[2]
        # Count current favorites
        fav_count = sum(1 for item in self.tree.get_children()
                        if self.tree.item(item, 'values')[0] == '*')
        if fav == '*':
            self.tree.item(sel[0], values=('', name, url))
        elif fav_count >= 6:
            messagebox.showinfo('Favoritos', 'Máximo 6 favoritos.', parent=self)
        else:
            self.tree.item(sel[0], values=('*', name, url))

    def _remove(self):
        sel = self.tree.selection()
        if sel:
            self.tree.delete(sel[0])

    def _save(self):
        accesses = []
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            fav, name, url = values[0], values[1], values[2]
            acc = {"name": name, "url": url}
            if fav == '*':
                acc["favorite"] = True
            accesses.append(acc)
        save_accesses(accesses)
        self.parent.accesses = accesses
        self.parent._refresh_access_combo()
        self.parent._build_favorites()
        self.destroy()


class SupportDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title('Soporte Técnico — Acredfy')
        self.geometry('680x520')
        self.resizable(True, True)
        self.minsize(500, 400)
        self.transient(parent)
        self.grab_set()
        self._build_ui()
        # Center on parent
        self.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        py = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f'+{px}+{py}')
        self.bind('<Escape>', lambda _: self.destroy())
        self._load_tickets()

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Tab 1: New ticket
        new_frame = ttk.Frame(notebook)
        notebook.add(new_frame, text='  Nuevo ticket  ')

        ttk.Label(new_frame, text='Asunto:', style='Section.TLabel').pack(anchor=tk.W, padx=12, pady=(12, 4))
        self.subject_var = tk.StringVar()
        ttk.Entry(new_frame, textvariable=self.subject_var, font=('Segoe UI', 10)).pack(fill=tk.X, padx=12)

        prio_frame = ttk.Frame(new_frame)
        prio_frame.pack(fill=tk.X, padx=12, pady=(8, 0))
        ttk.Label(prio_frame, text='Prioridad:', style='Section.TLabel').pack(side=tk.LEFT, padx=(0, 6))
        self.priority_var = tk.StringVar(value='Media')
        prio_combo = ttk.Combobox(prio_frame, textvariable=self.priority_var,
                                   values=['Baja', 'Media', 'Alta'], width=10, state='readonly')
        prio_combo.pack(side=tk.LEFT)

        ttk.Label(new_frame, text='Descripción:', style='Section.TLabel').pack(anchor=tk.W, padx=12, pady=(8, 4))
        self.desc_text = tk.Text(new_frame, wrap=tk.WORD, height=8, font=('Segoe UI', 10))
        self.desc_text.pack(fill=tk.BOTH, expand=True, padx=12)

        self.new_status = ttk.Label(new_frame, text='', style='Status.TLabel')
        self.new_status.pack(padx=12, pady=(4, 0))

        btn_frame = ttk.Frame(new_frame)
        btn_frame.pack(fill=tk.X, padx=12, pady=(4, 12))
        ttk.Button(btn_frame, text='Enviar ticket', style='Primary.TButton',
                   command=self._send_ticket).pack(side=tk.RIGHT)

        # Tab 2: My tickets
        list_frame = ttk.Frame(notebook)
        notebook.add(list_frame, text='  Mis tickets  ')

        columns = ('id', 'asunto', 'prioridad', 'estado', 'fecha')
        self.tickets_tree = ttk.Treeview(list_frame, columns=columns, show='headings',
                                          selectmode='browse', height=12)
        self.tickets_tree.heading('id', text='#')
        self.tickets_tree.heading('asunto', text='Asunto')
        self.tickets_tree.heading('prioridad', text='Prioridad')
        self.tickets_tree.heading('estado', text='Estado')
        self.tickets_tree.heading('fecha', text='Fecha')
        self.tickets_tree.column('id', width=40, minwidth=30)
        self.tickets_tree.column('asunto', width=250, minwidth=150)
        self.tickets_tree.column('prioridad', width=80, minwidth=60)
        self.tickets_tree.column('estado', width=90, minwidth=70)
        self.tickets_tree.column('fecha', width=90, minwidth=70)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tickets_tree.yview)
        self.tickets_tree.configure(yscrollcommand=scrollbar.set)
        self.tickets_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0), pady=12)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 12), pady=12)
        self.tickets_tree.bind('<Double-1>', self._on_ticket_double_click)

        self.list_status = ttk.Label(list_frame, text='Cargando...', style='StatusMuted.TLabel')
        # Don't pack this - it overlaps with tree. Use it if empty.

        # Tab 3: My account
        account_frame = ttk.Frame(notebook)
        notebook.add(account_frame, text='  Mi cuenta  ')

        info = get_license_info()
        company_name = info.get('company', '') if info else ''
        expires = info.get('expires_at', '')[:10] if info and info.get('expires_at') else ''

        ttk.Label(account_frame, text='Información de la cuenta',
                  style='Title.TLabel').pack(anchor=tk.W, padx=12, pady=(16, 8))

        details_frame = ttk.Frame(account_frame)
        details_frame.pack(fill=tk.X, padx=12, pady=(0, 12))

        ttk.Label(details_frame, text=f'Empresa: {company_name}',
                  font=('Segoe UI', 10)).pack(anchor=tk.W, pady=2)

        if expires:
            ttk.Label(details_frame, text=f'Suscripción activa hasta: {expires}',
                      font=('Segoe UI', 10), foreground=C['green']).pack(anchor=tk.W, pady=2)

        # Invoices button
        ttk.Button(account_frame, text='Ver mis facturas y método de pago',
                   command=self._open_billing_portal).pack(anchor=tk.W, padx=12, pady=(0, 4))

        self.portal_status = ttk.Label(account_frame, text='', style='Status.TLabel')
        self.portal_status.pack(anchor=tk.W, padx=12)

        ttk.Separator(account_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12, pady=12)

        ttk.Label(account_frame, text='Cancelar suscripción',
                  style='Section.TLabel').pack(anchor=tk.W, padx=12, pady=(0, 4))
        ttk.Label(account_frame,
                  text='Si cancelas, la aplicación seguirá funcionando hasta el final del periodo pagado. '
                       'No se realizarán más cobros.',
                  font=('Segoe UI', 9), foreground=C['text2'],
                  wraplength=550).pack(anchor=tk.W, padx=12, pady=(0, 8))

        self.cancel_status = ttk.Label(account_frame, text='', style='Status.TLabel')
        self.cancel_status.pack(anchor=tk.W, padx=12)

        ttk.Button(account_frame, text='Cancelar suscripción', style='Danger.TButton',
                   command=self._cancel_subscription).pack(anchor=tk.W, padx=12, pady=(4, 0))

    def _open_billing_portal(self):
        """Open Stripe Customer Portal in browser for invoices and billing management."""
        self.portal_status.config(text='Abriendo portal de facturación...', style='StatusMuted.TLabel')
        self.update_idletasks()

        def do_open():
            try:
                from app.auth import _post_authenticated
                import webbrowser
                result = _post_authenticated('subscription/portal', {})
                url = result.get('url', '')
                if url:
                    webbrowser.open(url)
                    self.after(0, lambda: self.portal_status.config(text=''))
                else:
                    self.after(0, lambda: self.portal_status.config(
                        text='No se pudo abrir el portal.', style='StatusErr.TLabel'))
            except Exception as e:
                self.after(0, lambda: self.portal_status.config(text=str(e), style='StatusErr.TLabel'))

        threading.Thread(target=do_open, daemon=True).start()

    def _cancel_subscription(self):
        if not messagebox.askyesno('Cancelar suscripción',
                                    '¿Estás seguro de que quieres cancelar tu suscripción?\n\n'
                                    'La aplicación seguirá funcionando hasta el final del periodo pagado.',
                                    parent=self):
            return

        self.cancel_status.config(text='Cancelando...', style='StatusMuted.TLabel')
        self.update_idletasks()

        def do_cancel():
            try:
                from app.auth import _post_authenticated
                result = _post_authenticated('subscription/cancel', {})
                detail = result.get('detail', 'Suscripción cancelada.')
                self.after(0, lambda: self.cancel_status.config(text=detail, style='StatusOk.TLabel'))
            except Exception as e:
                self.after(0, lambda: self.cancel_status.config(text=str(e), style='StatusErr.TLabel'))

        threading.Thread(target=do_cancel, daemon=True).start()

    def _send_ticket(self):
        subject = self.subject_var.get().strip()
        desc = self.desc_text.get('1.0', tk.END).strip()
        if not subject or not desc:
            self.new_status.config(text='Rellena el asunto y la descripción.', style='StatusErr.TLabel')
            return
        priority_map = {'Baja': 'baja', 'Media': 'media', 'Alta': 'alta'}
        priority = priority_map.get(self.priority_var.get(), 'media')
        self.new_status.config(text='Enviando...', style='StatusMuted.TLabel')
        self.update_idletasks()

        def do_send():
            try:
                from app.auth import _post_authenticated, LicenseError
                result = _post_authenticated('tickets', {
                    'subject': subject, 'description': desc, 'priority': priority
                })
                self.after(0, self._on_ticket_sent, None)
            except Exception as e:
                self.after(0, self._on_ticket_sent, str(e))

        threading.Thread(target=do_send, daemon=True).start()

    def _on_ticket_sent(self, error):
        if error:
            self.new_status.config(text=f'Error: {error}', style='StatusErr.TLabel')
        else:
            self.new_status.config(text='Ticket enviado correctamente.', style='StatusOk.TLabel')
            self.subject_var.set('')
            self.desc_text.delete('1.0', tk.END)
            self._load_tickets()

    def _load_tickets(self):
        def do_load():
            try:
                from app.auth import _get_authenticated
                tickets = _get_authenticated('tickets')
                self.after(0, self._on_tickets_loaded, tickets, None)
            except Exception as e:
                self.after(0, self._on_tickets_loaded, [], str(e))

        threading.Thread(target=do_load, daemon=True).start()

    def _on_tickets_loaded(self, tickets, error):
        self.tickets_tree.delete(*self.tickets_tree.get_children())
        if error:
            return
        for t in tickets:
            created = t.get('created_at', '')[:10] if t.get('created_at') else ''
            prio_labels = {'baja': 'Baja', 'media': 'Media', 'alta': 'Alta'}
            status_labels = {'abierto': 'Abierto', 'en_progreso': 'En progreso',
                           'resuelto': 'Resuelto', 'cerrado': 'Cerrado'}
            self.tickets_tree.insert('', tk.END, iid=str(t['id']), values=(
                t['id'], t['subject'],
                prio_labels.get(t.get('priority', ''), t.get('priority', '')),
                status_labels.get(t.get('status', ''), t.get('status', '')),
                created,
            ))

    def _on_ticket_double_click(self, event):
        sel = self.tickets_tree.selection()
        if sel:
            ticket_id = sel[0]
            TicketDetailDialog(self, ticket_id)


class TicketDetailDialog(tk.Toplevel):
    def __init__(self, parent, ticket_id):
        super().__init__(parent)
        self.parent = parent
        self.ticket_id = ticket_id
        self.title(f'Ticket #{ticket_id}')
        self.geometry('580x480')
        self.resizable(True, True)
        self.minsize(400, 350)
        self.transient(parent)
        self.grab_set()
        self._build_ui()
        self.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        py = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f'+{px}+{py}')
        self.bind('<Escape>', lambda _: self.destroy())
        self._load_detail()

    def _build_ui(self):
        # Header
        self.title_label = ttk.Label(self, text='Cargando...', style='Title.TLabel')
        self.title_label.pack(anchor=tk.W, padx=12, pady=(12, 2))
        self.info_label = ttk.Label(self, text='', style='Subtitle.TLabel')
        self.info_label.pack(anchor=tk.W, padx=12, pady=(0, 8))

        # Messages area (read-only Text widget)
        msg_frame = ttk.Frame(self)
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=12)
        self.messages_text = tk.Text(msg_frame, wrap=tk.WORD, state=tk.DISABLED,
                                      font=('Segoe UI', 10), bg='#f8fafc', relief=tk.FLAT)
        msg_scroll = ttk.Scrollbar(msg_frame, orient=tk.VERTICAL, command=self.messages_text.yview)
        self.messages_text.configure(yscrollcommand=msg_scroll.set)
        self.messages_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        msg_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Configure text tags for styling
        self.messages_text.tag_configure('admin_name', foreground='#2563eb', font=('Segoe UI', 9, 'bold'))
        self.messages_text.tag_configure('user_name', foreground='#16a34a', font=('Segoe UI', 9, 'bold'))
        self.messages_text.tag_configure('timestamp', foreground='#94a3b8', font=('Segoe UI', 8))
        self.messages_text.tag_configure('body', font=('Segoe UI', 10))
        self.messages_text.tag_configure('separator', foreground='#e2e8f0')

        # Reply area
        reply_frame = ttk.Frame(self)
        reply_frame.pack(fill=tk.X, padx=12, pady=(8, 4))
        ttk.Label(reply_frame, text='Responder:', style='Section.TLabel').pack(anchor=tk.W)
        self.reply_text = tk.Text(reply_frame, wrap=tk.WORD, height=3, font=('Segoe UI', 10))
        self.reply_text.pack(fill=tk.X, pady=(4, 0))

        self.reply_status = ttk.Label(self, text='', style='Status.TLabel')
        self.reply_status.pack(padx=12)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(btn_frame, text='Enviar', style='Primary.TButton',
                   command=self._send_reply).pack(side=tk.RIGHT)

    def _load_detail(self):
        def do_load():
            try:
                from app.auth import _get_authenticated
                data = _get_authenticated(f'tickets/{self.ticket_id}')
                self.after(0, self._on_detail_loaded, data, None)
            except Exception as e:
                self.after(0, self._on_detail_loaded, None, str(e))
        threading.Thread(target=do_load, daemon=True).start()

    def _on_detail_loaded(self, data, error):
        if error:
            self.title_label.config(text=f'Error: {error}')
            return
        status_labels = {'abierto': 'Abierto', 'en_progreso': 'En progreso',
                        'resuelto': 'Resuelto', 'cerrado': 'Cerrado'}
        self.title_label.config(text=data['subject'])
        self.info_label.config(text=f"Estado: {status_labels.get(data['status'], data['status'])} | "
                                    f"Prioridad: {data['priority'].capitalize()}")

        # Show description + messages
        self.messages_text.config(state=tk.NORMAL)
        self.messages_text.delete('1.0', tk.END)

        # Description
        self.messages_text.insert(tk.END, 'Tu ', 'user_name')
        created = data.get('created_at', '')[:16].replace('T', ' ') if data.get('created_at') else ''
        self.messages_text.insert(tk.END, f'  {created}\n', 'timestamp')
        self.messages_text.insert(tk.END, data['description'] + '\n', 'body')
        self.messages_text.insert(tk.END, '\n' + '─' * 50 + '\n\n', 'separator')

        # Messages
        for msg in data.get('messages', []):
            if msg['is_admin']:
                self.messages_text.insert(tk.END, 'Soporte ', 'admin_name')
            else:
                self.messages_text.insert(tk.END, 'Tu ', 'user_name')
            ts = msg.get('created_at', '')[:16].replace('T', ' ') if msg.get('created_at') else ''
            self.messages_text.insert(tk.END, f'  {ts}\n', 'timestamp')
            self.messages_text.insert(tk.END, msg['body'] + '\n\n', 'body')

        self.messages_text.config(state=tk.DISABLED)
        self.messages_text.see(tk.END)

    def _send_reply(self):
        body = self.reply_text.get('1.0', tk.END).strip()
        if not body:
            return
        self.reply_status.config(text='Enviando...', style='StatusMuted.TLabel')
        self.update_idletasks()

        def do_send():
            try:
                from app.auth import _post_authenticated
                _post_authenticated(f'tickets/{self.ticket_id}/messages', {'body': body})
                self.after(0, self._on_reply_sent, None)
            except Exception as e:
                self.after(0, self._on_reply_sent, str(e))

        threading.Thread(target=do_send, daemon=True).start()

    def _on_reply_sent(self, error):
        if error:
            self.reply_status.config(text=f'Error: {error}', style='StatusErr.TLabel')
        else:
            self.reply_status.config(text='')
            self.reply_text.delete('1.0', tk.END)
            self._load_detail()
            if hasattr(self.parent, '_load_tickets'):
                self.parent._load_tickets()


class ActivationScreen(tk.Tk):
    """Pantalla de activacion de licencia — se muestra antes del app principal."""

    def __init__(self):
        super().__init__()
        self.title('Acredfy — Activación')
        self.geometry('460x340')
        self.resizable(False, False)

        apply_theme(self)
        self._build_ui()
        self._center_window()

    def _center_window(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f'+{x}+{y}')

    def _build_ui(self):
        pad = 24

        # Header
        ttk.Label(self, text='Acredfy', style='Title.TLabel').pack(pady=(pad, 4))
        ttk.Label(self, text=f'v{APP_VERSION}', style='Subtitle.TLabel').pack()

        # Instruction
        ttk.Label(self, text='Introduce tu clave de licencia para activar el producto.',
                  style='Subtitle.TLabel', wraplength=380).pack(pady=(20, 12))

        # License key entry
        key_frame = ttk.Frame(self)
        key_frame.pack(fill=tk.X, padx=pad)
        ttk.Label(key_frame, text='Clave de licencia:', style='Section.TLabel').pack(anchor=tk.W, pady=(0, 4))
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(key_frame, textvariable=self.key_var, font=('Consolas', 11))
        self.key_entry.pack(fill=tk.X)
        self.key_entry.focus_set()
        self.key_entry.bind('<Return>', lambda _: self._activate())

        # Status label
        self.status_label = ttk.Label(self, text='', style='Status.TLabel', wraplength=380)
        self.status_label.pack(pady=(12, 0))

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=(16, 8))
        ttk.Button(btn_frame, text='Activar', style='Primary.TButton',
                   command=self._activate).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text='Salir', command=self.destroy).pack(side=tk.LEFT)

        # Links
        import webbrowser
        links_frame = ttk.Frame(self)
        links_frame.pack(pady=(0, pad))
        no_key = tk.Label(links_frame, text='¿No tienes clave? Prueba gratis en ',
                          font=('Segoe UI', 9), fg=C['text2'], bg=C['bg'], cursor='')
        no_key.pack(side=tk.LEFT)
        web_link = tk.Label(links_frame, text='acredfy.com',
                            font=('Segoe UI', 9, 'underline'), fg=C['primary'], bg=C['bg'], cursor='hand2')
        web_link.pack(side=tk.LEFT)
        web_link.bind('<Button-1>', lambda _: webbrowser.open('https://acredfy.com/registro'))

        contact_frame = ttk.Frame(self)
        contact_frame.pack()
        tk.Label(contact_frame, text='Contacto: ',
                 font=('Segoe UI', 9), fg=C['text2'], bg=C['bg']).pack(side=tk.LEFT)
        email_link = tk.Label(contact_frame, text='info@acredfy.com',
                              font=('Segoe UI', 9, 'underline'), fg=C['primary'], bg=C['bg'], cursor='hand2')
        email_link.pack(side=tk.LEFT)
        email_link.bind('<Button-1>', lambda _: webbrowser.open('mailto:info@acredfy.com'))

    def _activate(self):
        key = self.key_var.get().strip()
        if not key:
            self.status_label.config(text='Introduce una clave de licencia.', style='StatusErr.TLabel')
            return

        self.status_label.config(text='Activando...', style='StatusMuted.TLabel')
        self.update_idletasks()

        try:
            result = activate_license_key(key)
            company = result.get('company', '')
            self.status_label.config(
                text=f'Licencia activada: {company}',
                style='StatusOk.TLabel')
            self.after(1000, self._launch_main)
        except LicenseError as e:
            self.status_label.config(text=str(e), style='StatusErr.TLabel')
        except Exception as e:
            self.status_label.config(text=f'Error: {e}', style='StatusErr.TLabel')

    def _launch_main(self):
        self.destroy()
        app = AcredfyApp(startup_url=_parse_startup_url())
        app.mainloop()


def _parse_startup_url():
    """Parse URL from command-line arguments (acredfy:// protocol or direct URL)."""
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        # Handle acredfy://https://... protocol
        if arg.startswith('acredfy://'):
            url = arg[len('acredfy://'):]
            if url and not url.startswith('http'):
                url = 'https://' + url
            return url
        # Handle direct URL argument
        if arg.startswith('http'):
            return arg
    return None


def main():
    """Entry point: check license, show activation screen or main app."""
    startup_url = _parse_startup_url()
    if is_licensed():
        app = AcredfyApp(startup_url=startup_url)
        app.mainloop()
    else:
        screen = ActivationScreen()
        screen.mainloop()


if __name__ == '__main__':
    main()
