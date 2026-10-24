# OFOQ Recon

A low-impact web security assessment tool for **Termux** and **Kali Linux**. It produces terminal results plus HTML and JSON reports.

## Included checks

- DNS resolution and IP display
- HTTP response status, redirects, and basic response metadata
- HTTPS certificate details and expiry checks
- Security-header presence checks (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Basic CORS header observation
- Checks whether `robots.txt` and `sitemap.xml` respond
- HTML and JSON reports

> This tool is intentionally non-exploitative. It does not attempt SQL injection, XSS payload injection, credential guessing, authentication bypass, destructive testing, or exploitation. Missing headers are indicators, not proof of a vulnerability.

## Authorization and safe defaults

Only scan systems you own or have explicit permission to assess. Public targets are checked with low-impact GET requests. Private/special-use IP addresses are blocked by default. To test your own local lab, pass `--allow-private`.

## Install on Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
unzip ofoq_recon.zip
cd ofoq_recon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Install on Termux

Install Termux from a trusted source, then:

```bash
pkg update && pkg upgrade
pkg install python unzip
unzip ofoq_recon.zip
cd ofoq_recon
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If Termux rejects installation due to a package/build issue, update Termux and its packages first. This project does not require root access.

## Run

Interactive mode:

```bash
python main.py
```

Direct scan:

```bash
python main.py https://example.com
```

Choose a custom report directory:

```bash
python main.py https://example.com --out reports
```

For a private/local target in your own authorized lab only:

```bash
python main.py http://192.168.1.10 --allow-private
```

Output files appear in `reports/` by default:
- `hostname_TIMESTAMP.json`
- `hostname_TIMESTAMP.html`

## Interpretation notes

- `potential` means a configuration indicator worth reviewing; it is not proof of exploitability.
- `inconclusive` means the tool could not reliably complete that check.
- `observed` means the response or certificate condition was directly observed.
- Some headers are optional depending on application architecture; validate each recommendation against the app.
- This version uses a bounded response read and a short timeout. Authenticated applications and JavaScript-rendered behavior are outside its scope.

## Project structure

```text
ofoq_recon/
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Troubleshooting

- `ModuleNotFoundError`: activate the virtual environment (Kali) or reinstall requirements (Termux).
- DNS failure: check the hostname and network.
- TLS error: verify the certificate and whether the target supports modern HTTPS.
- Private target blocked: only if this is your own lab, rerun with `--allow-private`.
