from colorama import Fore, Style

def print_banner():
    banner = f"""
{Fore.RED}
 _____ _____ _____ _____ _     _ _ _     _ 
|   __|   __|__   |  ___| |   | | | |   | |
|__   |__   |  /  |___  | |___| | | |   | |
|_____|_____|_/_____|_____|_____|_|_|_____|_|
{Style.RESET_ALL}
{Fore.CYAN}  SS7 Vulnerability Assessment & SMS Security Testing Tool{Style.RESET_ALL}
{Fore.YELLOW}  For Educational & Authorized Security Testing Only{Style.RESET_ALL}
{Fore.GREEN}  Version: 1.0  |  SOC Portfolio Project{Style.RESET_ALL}
{Fore.RED}  Use only on systems you have permission to test{Style.RESET_ALL}
    """
    print(banner)

def print_section(title):
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  [*] {title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

def print_success(msg):
    print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")

def print_warning(msg):
    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")

def print_error(msg):
    print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")

def print_info(msg):
    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")