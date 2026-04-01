# SS7Shield 🛡️

> SS7 Vulnerability Assessment & SMS Security Testing Tool

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Category-Security-red?style=flat-square)
![SOC](https://img.shields.io/badge/Use__Case-SOC__Portfolio-navy?style=flat-square)

A Python-based CLI security tool that assesses **SS7 protocol vulnerabilities** and **SMS 2FA weaknesses** — demonstrating how telecom-level attacks enable Account Takeover (ATO).

---

## 🔍 What is SS7Shield?

SS7 (Signalling System #7) is the backbone protocol of global telecom networks. Designed in the 1980s **with no authentication**, it allows an attacker with SS7 access to:

- 📍 Track a subscriber's real-time location (city → GPS level)
- 📨 Intercept SMS messages (OTPs, bank codes, 2FA tokens)
- 🔓 Bypass SMS-based 2FA → **Full Account Takeover**
- 📞 Record or redirect phone calls silently
- 🚫 Disable calls, SMS, and data for any subscriber

---

## 🧩 Modules

| Module | Checks | Description |
|--------|:------:|-------------|
| `vulnerability_scanner.py` | 8 | SS7 protocol-level attack vector assessment |
| `sms_2fa_tester.py` | 9 | SMS OTP implementation weakness detection |
| `sim_swap_detector.py` | 6 | Application-layer SIM swap protection checks |
| `report_generator.py` | — | HTML + TXT professional SOC reports |

---

## ⚡ Quick Start

```bash
git clone https://github.com/muhammed95rafi-arch/ss7shield.git
cd ss7shield
pip install -r requirements.txt
python main.py --demo
python main.py --target https://example.com
```

---

## 📊 Sample Output

```
============================================================
  [*] MODULE 1: SS7 VULNERABILITY ASSESSMENT
============================================================
  [-] CRITICAL: anyTimeInterrogation (ATI) Exposed
  [-] CRITICAL: Unauthenticated updateLocation
  [-] CRITICAL: SMS Interception via HLR Manipulation
  [!] HIGH:     Call Interception via CAMEL
  [!] HIGH:     IMSI Disclosure
  [+] PROTECTED: Denial of Service via VLR Manipulation
  [*] Risk Score : 48/100  |  Risk Level : CRITICAL RISK
============================================================
  [*] MODULE 2: SMS 2FA SECURITY TESTING
============================================================
  [+] HTTPS enabled — Transport layer secure
  [+] OTP length: 6 digits — Acceptable
  [!] No rate limiting detected — CRITICAL
  [!] SMS is the ONLY 2FA method — High SS7 risk!
============================================================
  [+] HTML Report → reports/ss7shield_report_20260401.html
  [*] Overall Risk Level : CRITICAL RISK
============================================================
```

---

## 📁 Project Structure

```
ss7shield/
├── main.py
├── modules/
│   ├── vulnerability_scanner.py
│   ├── sms_2fa_tester.py
│   ├── sim_swap_detector.py
│   └── report_generator.py
├── utils/
│   ├── banner.py
│   └── logger.py
├── requirements.txt
└── README.md
```

---

## 🛡️ SS7 Vulnerability Coverage

| Severity | Vulnerability | Impact |
|----------|--------------|--------|
| 🔴 CRITICAL | anyTimeInterrogation (ATI) | Real-time location tracking |
| 🔴 CRITICAL | Unauthenticated updateLocation | SMS hijack, 2FA bypass |
| 🔴 CRITICAL | SMS Interception via HLR | OTP theft, Account Takeover |
| 🟠 HIGH | CAMEL Call Intercept | Silent call recording |
| 🟠 HIGH | IMSI Disclosure | Subscriber identity exposure |
| 🟠 HIGH | DoS via VLR | Service disruption |
| 🟡 MEDIUM | TMSI De-anonymization | Subscriber identification |
| 🟡 MEDIUM | LCS Auth Bypass | GPS-level location tracking |

---

## 📋 Requirements

```
Python 3.8+
requests==2.31.0
colorama==0.4.6
```

---

## ⚠️ Legal Disclaimer

> This tool is for **educational purposes** and **authorized security testing only**.
> Only use on systems you have **explicit permission** to test.
> The author is not responsible for any misuse or damage.

---

## 📚 References

- Tobias Engel — *SS7: Locate. Track. Manipulate.* (CCC 2014)
- NIST SP 800-63B — SMS OTP not recommended as sole 2FA
- GSMA FS.11 — SS7 Interconnect Security Monitoring Guidelines
- 3GPP TS 29.002 — Mobile Application Part (MAP) Specification
- RFC 6238 — TOTP: Time-Based One-Time Password Algorithm

---

## 👤 Author

**Muhammad Khan**
Certified Penetration Tester (CPT) | Qnayds Academy
Department of Cyber Security

[![GitHub](https://img.shields.io/badge/GitHub-muhammed95rafi--arch-black?style=flat-square&logo=github)](https://github.com/muhammed95rafi-arch)
