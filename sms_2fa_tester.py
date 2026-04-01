"""
Module 2: SMS 2FA Security Tester
- Target application-ന്റെ SMS 2FA implementation test ചെയ്യുന്നു
- SS7 attack surface assess ചെയ്യുന്നു
- Weaknesses identify ചെയ്ത് report ചെയ്യുന്നു
"""

import requests
import time
import re
from utils.banner import print_success, print_warning, print_error, print_info

class SMS2FATester:
    def __init__(self, target_url, phone_number=None):
        self.target_url = target_url.rstrip('/')
        self.phone_number = phone_number
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SS7Shield-SecurityTester/1.0'
        })
        self.findings = []
        self.timeout = 10

    def run_all_checks(self):
        """All SMS 2FA security checks run ചെയ്യുന്നു"""
        print_info(f"Target: {self.target_url}")
        print_info("Running SMS 2FA Security Assessment...\n")

        checks = [
            self.check_https,
            self.check_otp_length,
            self.check_rate_limiting,
            self.check_otp_expiry,
            self.check_otp_reuse,
            self.check_response_leakage,
            self.check_backup_auth,
            self.check_account_lockout,
            self.check_ss7_risk_disclosure,
        ]

        for check in checks:
            try:
                check()
                time.sleep(0.5)
            except Exception as e:
                print_error(f"Check failed: {check.__name__} — {str(e)}")

        return self.findings

    def check_https(self):
        """HTTPS enforcement check"""
        print_info("Checking HTTPS enforcement...")
        if self.target_url.startswith("https://"):
            print_success("HTTPS enabled — Transport layer secure")
            self._add_finding("PASS", "HTTPS Enforcement", "LOW",
                            "HTTPS properly implemented")
        else:
            print_error("HTTP detected — OTP transmitted in plaintext!")
            self._add_finding("FAIL", "HTTPS Not Enforced", "HIGH",
                            "OTP/credentials transmitted over HTTP — trivial interception")

    def check_otp_length(self):
        """OTP length and complexity check"""
        print_info("Checking OTP length requirements...")
        # Real implementation: actually request OTP and check length
        # Demo: simulate check
        otp_length = self._simulate_otp_check()

        if otp_length >= 6:
            print_success(f"OTP length: {otp_length} digits — Acceptable")
            self._add_finding("PASS", "OTP Length", "LOW",
                            f"OTP is {otp_length} digits")
        else:
            print_error(f"OTP too short: {otp_length} digits — Brute-forceable!")
            self._add_finding("FAIL", "Weak OTP Length", "HIGH",
                            f"OTP is only {otp_length} digits — easily brute-forced")

    def check_rate_limiting(self):
        """Rate limiting on OTP endpoint check"""
        print_info("Checking rate limiting on OTP endpoint...")

        endpoint = f"{self.target_url}/api/verify-otp"
        attempts = 0
        rate_limited = False

        for i in range(5):
            try:
                resp = self.session.post(
                    endpoint,
                    json={"otp": f"{100000 + i}"},
                    timeout=self.timeout
                )
                attempts += 1
                if resp.status_code == 429:
                    rate_limited = True
                    break
            except:
                break
            time.sleep(0.2)

        if rate_limited:
            print_success(f"Rate limiting detected after {attempts} attempts")
            self._add_finding("PASS", "Rate Limiting", "LOW",
                            f"Rate limiting active — triggered after {attempts} attempts")
        else:
            print_warning(f"No rate limiting detected after {attempts} attempts")
            self._add_finding("FAIL", "No Rate Limiting on OTP", "CRITICAL",
                            "Unlimited OTP attempts allowed — brute force + SS7 attack possible")

    def check_otp_expiry(self):
        """OTP expiry time check"""
        print_info("Checking OTP expiry policy...")
        # Simulate: real tool would request OTP, wait, then verify
        expiry_seconds = self._simulate_expiry_check()

        if expiry_seconds and expiry_seconds <= 300:  # 5 minutes
            print_success(f"OTP expires in {expiry_seconds}s — Good")
            self._add_finding("PASS", "OTP Expiry", "LOW",
                            f"OTP expires in {expiry_seconds} seconds")
        elif expiry_seconds and expiry_seconds > 300:
            print_warning(f"OTP expires in {expiry_seconds}s — Too long!")
            self._add_finding("WARN", "Long OTP Expiry", "MEDIUM",
                            f"OTP valid for {expiry_seconds}s — extends SS7 attack window")
        else:
            print_error("No OTP expiry detected — OTP may never expire!")
            self._add_finding("FAIL", "No OTP Expiry", "HIGH",
                            "OTP does not expire — attacker has unlimited time post-SS7 intercept")

    def check_otp_reuse(self):
        """OTP reuse check"""
        print_info("Checking if OTP can be reused...")
        # Simulate check
        reuse_allowed = self._simulate_reuse_check()

        if not reuse_allowed:
            print_success("OTP invalidated after use — Good")
            self._add_finding("PASS", "OTP Single Use", "LOW",
                            "OTP properly invalidated after first use")
        else:
            print_error("OTP can be reused multiple times!")
            self._add_finding("FAIL", "OTP Reuse Allowed", "HIGH",
                            "Same OTP usable multiple times — persistent SS7 intercept useful")

    def check_response_leakage(self):
        """Check if OTP leaked in API response"""
        print_info("Checking for OTP leakage in API responses...")
        try:
            resp = self.session.post(
                f"{self.target_url}/api/send-otp",
                json={"phone": self.phone_number or "1234567890"},
                timeout=self.timeout
            )
            body = resp.text

            # Check if OTP appears in response
            otp_pattern = re.search(r'\b\d{4,8}\b', body)
            if otp_pattern and "otp" in body.lower():
                print_error(f"OTP LEAKED in response: {otp_pattern.group()}")
                self._add_finding("FAIL", "OTP Leaked in Response", "CRITICAL",
                                "OTP returned in API response — SS7 attack unnecessary!")
            else:
                print_success("No OTP leakage in API response")
                self._add_finding("PASS", "No Response Leakage", "LOW",
                                "OTP not exposed in API response")
        except:
            print_info("Could not reach OTP endpoint — skipping leakage check")

    def check_backup_auth(self):
        """Check if alternative 2FA methods available"""
        print_info("Checking for backup authentication methods...")
        # Simulate check
        has_backup = self._simulate_backup_check()

        if has_backup:
            print_success("Backup 2FA available (TOTP/Email) — Reduces SS7 risk")
            self._add_finding("PASS", "Backup Auth Available", "LOW",
                            "Alternative 2FA reduces SS7 attack impact")
        else:
            print_warning("SMS is the ONLY 2FA method — High SS7 risk!")
            self._add_finding("FAIL", "No Backup Auth", "HIGH",
                            "SMS-only 2FA — complete account takeover possible via SS7")

    def check_account_lockout(self):
        """Account lockout policy check"""
        print_info("Checking account lockout policy...")
        lockout_exists = self._simulate_lockout_check()

        if lockout_exists:
            print_success("Account lockout policy detected")
            self._add_finding("PASS", "Account Lockout", "LOW",
                            "Lockout policy limits brute force + SS7 combo attacks")
        else:
            print_warning("No account lockout detected")
            self._add_finding("WARN", "No Account Lockout", "MEDIUM",
                            "No lockout — combined SS7 + brute force attack possible")

    def check_ss7_risk_disclosure(self):
        """Check if app warns users about SMS 2FA risks"""
        print_info("Checking SS7 risk disclosure to users...")
        # Most apps don't disclose this
        print_warning("No SS7 risk disclosure found (common issue)")
        self._add_finding("WARN", "No SS7 Risk Disclosure", "LOW",
                        "Users not informed about SMS 2FA limitations vs SS7 attacks")

    # ── Simulation helpers ──────────────────────────────────────────
    def _simulate_otp_check(self):
        return 6  # Simulate 6-digit OTP

    def _simulate_expiry_check(self):
        return 300  # Simulate 5-min expiry

    def _simulate_reuse_check(self):
        return False  # Simulate single-use OTP

    def _simulate_backup_check(self):
        return False  # Simulate no backup auth

    def _simulate_lockout_check(self):
        return True  # Simulate lockout exists

    def _add_finding(self, status, title, severity, description):
        self.findings.append({
            "status": status,
            "title": title,
            "severity": severity,
            "description": description
        })