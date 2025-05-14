# ☠️ CNAME Reaper — Reaping Dead DNS Records ⚔️

CNAME Reaper is a command-line tool designed to detect **dangling DNS records** and potential **subdomain takeover vulnerabilities**. It helps identify misconfigured or unclaimed cloud-based subdomain records that could be exploited by attackers.

---

## 🔍 What Are Dangling DNS Records?

Dangling DNS records occur when a subdomain points to an external service (via a CNAME or other record), but that service is no longer active or claimed. This can allow attackers to **take over** the subdomain by registering the unclaimed service.

### 💥 Why Is This a Problem?

- Attackers can impersonate legitimate services.
- They may host phishing pages or serve malware.
- It undermines trust in the target organization.

---

## 🛠 Features

- ✅ Detects unclaimed CNAME targets
- ✅ Uses banner grabbing to verify unconfigured service pages
- ✅ Supports single domain or list input
- ✅ Auto-enumerates subdomains via [crt.sh](https://crt.sh)
- ✅ Categorizes by provider (AWS, Azure, Google, etc.)
- ✅ Outputs to screen, `.txt`, `.csv`, and `.json`

---

## 🚀 Installation

```bash
git clone https://github.com/mrander5on/cname-reaper.git
cd cname-reaper
chmod +x cname_reaper.py
```

---

## ⚙️ Usage

```bash
./cname_reaper.py -d example.com
./cname_reaper.py -sl subdomains.txt --incl-safe -oa
```

### 🔧 Flags

| Flag                 | Description                                     |
|----------------------|-------------------------------------------------|
| `-d` / `--domain`    | Single apex domain (e.g., example.com)          |
| `-dl`                | File with list of apex domains                  |
| `-s` / `--subdomain` | Single subdomain (e.g., app.example.com)        |
| `-sl`                | File with subdomains                            |
| `--incl-safe`        | Show safe (non-vulnerable) results              |
| `-ot`                | Output results to text file                     |
| `-oc`                | Output results to CSV                           |
| `-oj`                | Output results to JSON                          |
| `-oa`                | Output to all formats                           |

---

## 🧪 Example Output

```bash
=== Potentially Vulnerable Subdomains ===

--- Azure ---
shop.example.com -> shop.azurewebsites.net

--- GitHub Pages ---
blog.example.com -> user.github.io

=== Safe Subdomains ===
www.example.com -> active-host.net
```

In CSV/JSON output, each entry includes:

- `Subdomain`
- `CNAME`
- `Provider` (or `"None"` if no CNAME)
- `Status` ("Vulnerable" or "Safe")
- `Reason` ("NXDOMAIN" or "Banner"")

---

## 📚 Blog Post

Read the full release announcement here: [Coming Soon](#)

---

## 🙏 Acknowledgments

- Sprocket Security (sprocketsecurity.com)
- crt.sh for certificate-based subdomain enumeration


---

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Use it responsibly.

---

## 📄 License

MIT License
