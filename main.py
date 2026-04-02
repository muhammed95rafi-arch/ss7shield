#!/usr/bin/env python3
"""
SS7Shield — SS7 Vulnerability Assessment & SMS Security Testing Tool
SOC Portfolio Project
"""

import argparse
import sys
import time

from utils.banner import (print_banner, print_section,
                           print_success, print_warning,
                           print_error, print_info)
from utils.logger import setup_logger, log_finding
from modules.vulnerability_scanner import (run_scanner,
                                           get_risk_level,
                                           SS7_VULNERABILITIES)
from modules.sms_2fa_tester import SMS2FATester
from modules.sim_swap_detector import SIMSwapDetector
from modules.report_generator import generate_report

# --- Added Function to save results ---
def save_scan_result(result_text):
    with open("scan_results.txt", "a") as file:
        file.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] " + result_text + "\n")

def parse_args():
    parser = argparse.ArgumentParser(
        description="SS7Shield — SS7 Vulnerability & SMS Security Tester"
    )
    parser.add_argument('--target', '-t',
                        help='Target URL (e.g. https://example.com)')
    parser.add_argument('--phone', '-p',
                        help='Phone number for SMS 2FA testing')
    parser.add_argument('--demo', action='store_true',
                        help='Run in demo mode with sample target')
    parser.add_argument('--skip-ss7', action='store_true',
                        help='Skip SS7 vulnerability scan')
    parser.add_argument('--skip-sms', action='store_true',
                        help='Skip SMS 2FA tests')
    parser.add_argument('--skip-sim', action='store_true',
                        help='Skip SIM swap checks')
    return parser.parse_args()

def confirm_authorization(target):
    print_warning("AUTHORIZATION CHECK")
    print_warning(f"Target: {target}")
    print_warning("Only test systems you have explicit permission to test.")
    confirm = input("\n  Do you have authorization to test this target? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print_error("Aborted — Authorization not confirmed.")
        sys.exit(0)
    print_success("Authorization confirmed. Proceeding...\n")
    time.sleep(1)

def run_full_assessment(args, logger):
    target = args.target or "https://example.com"
    phone  = args.phone

    ss7_findings  = []
    sms_findings  = []
    sim_findings  = []
    risk_score    = 0

    save_scan_result(f"Starting assessment for target: {target}")

    # -- Module 1: SS7 Scan --
    if not args.skip_ss7:
        print_section("MODULE 1: SS7 VULNERABILITY ASSESSMENT")
        ss7_findings, risk_score = run_scanner()
        save_scan_result(f"Module 1 Complete: Found {len(ss7_findings)} SS7 vulnerabilities. Risk Score: {risk_score}")

    # -- Module 2: SMS Test --
    if not args.skip_sms:
        print_section("MODULE 2: SMS 2FA SECURITY TESTING")
        tester = SMS2FATester(target, phone)
        sms_findings = tester.run_all_checks()
        save_scan_result(f"Module 2 Complete: SMS 2FA checks finished.")

    # -- Module 3: SIM Swap --
    if not args.skip_sim:
        print_section("MODULE 3: SIM SWAP RISK ASSESSMENT")
        detector = SIMSwapDetector(target)
        sim_findings = detector.run_checks()
        save_scan_result(f"Module 3 Complete: SIM swap risk assessment finished.")

    # -- Module 4: Report Generation --
    print_section("MODULE 4: GENERATING REPORT")
    html_path, txt_path = generate_report(
        ss7_findings, sms_findings, sim_findings,
        risk_score, target
    )
    save_scan_result(f"Reports generated: {txt_path}")

    return html_path, txt_path, risk_score

def print_summary(risk_score, html_path, txt_path):
    print_section("ASSESSMENT COMPLETE")
    risk = get_risk_level(risk_score)
    print_info(f"Overall Risk Level : {risk}")
    print_info(f"Risk Score         : {risk_score}/100")
    print_success(f"HTML Report        : {html_path}")
    print_success(f"TXT  Report        : {txt_path}")

def main():
    print_banner()
    args = parse_args()
    logger, log_file = setup_logger()

    if args.demo:
        print_info("Running in DEMO mode — no real network requests\n")
        args.target = "https://example.com"
    elif not args.target:
        print_error("Please provide a target: --target https://example.com")
        sys.exit(1)
    else:
        confirm_authorization(args.target)

    try:
        html_path, txt_path, risk_score = run_full_assessment(args, logger)
        print_summary(risk_score, html_path, txt_path)
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
