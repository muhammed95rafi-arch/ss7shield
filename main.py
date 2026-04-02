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
from utils.logger import setup_logger
from modules.vulnerability_scanner import run_scanner, get_risk_level
from modules.sms_2fa_tester import SMS2FATester
from modules.sim_swap_detector import SIMSwapDetector
from modules.report_generator import generate_report

def parse_args():
    parser = argparse.ArgumentParser(
        description="SS7Shield — SS7 Vulnerability & SMS Security Tester"
    )
    parser.add_argument('--target', '-t', required=True,
                        help='Target Phone Number or IP (e.g. 9562791883 or 8.8.8.8)')
    parser.add_argument('--shodan', help='Your Shodan API Key for network info')
    parser.add_argument('--numverify', help='Your NumVerify API Key for carrier info')
    parser.add_argument('--demo', action='store_true',
                        help='Run in demo mode with sample target')
    parser.add_argument('--skip-sms', action='store_true', help='Skip SMS 2FA tests')
    parser.add_argument('--skip-sim', action='store_true', help='Skip SIM swap checks')
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
    target = args.target
    shodan_key = args.shodan
    numverify_key = args.numverify

    ss7_findings  = []
    sms_findings  = []
    sim_findings  = []
    risk_score    = 0

    # -- Module 1: SS7 & Info Lookup --
    print_section("MODULE 1: SS7 VULNERABILITY & INFO LOOKUP")
    ss7_findings, risk_score = run_scanner(target, shodan_key, numverify_key)

    # -- Module 2: SMS Test --
    if not args.skip_sms:
        print_section("MODULE 2: SMS 2FA SECURITY TESTING")
        tester = SMS2FATester(target, None)
        sms_findings = tester.run_all_checks()

    # -- Module 3: SIM Swap --
    if not args.skip_sim:
        print_section("MODULE 3: SIM SWAP RISK ASSESSMENT")
        detector = SIMSwapDetector(target)
        sim_findings = detector.run_checks()

    # -- Module 4: Report Generation --
    print_section("MODULE 4: GENERATING REPORTS")
    html_path, txt_path = generate_report(
        ss7_findings, sms_findings, sim_findings,
        risk_score, target
    )

    return html_path, txt_path, risk_score

def main():
    print_banner()
    args = parse_args()
    logger, log_file = setup_logger()

    if args.demo:
        print_info("Running in DEMO mode...\n")
    
    confirm_authorization(args.target)

    try:
        html_path, txt_path, risk_score = run_full_assessment(args, logger)
        
        print_section("ASSESSMENT COMPLETE")
        print_info(f"Overall Risk Level : {get_risk_level(risk_score)}")
        print_info(f"Risk Score         : {risk_score}/100")
        print_success(f"HTML Dashboard     : {html_path}")
        print_success(f"Text Report        : {txt_path}")
        
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
