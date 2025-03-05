import requests
import concurrent.futures
import argparse
import time
import sys
import random
import threading
from colorama import Fore, Style, init
from fake_useragent import UserAgent
import cloudscraper


print_lock = threading.Lock()


def safe_print(message):
    with print_lock:
        print(message)


init(autoreset=True)

LOGO = rf'''{Fore.CYAN}
.oPYo.                     8        o   o               
8    8                     8        `b d'               
8      oPYo. .oPYo. .oPYo. 8  .o     `b'  .oPYo. o    o 
8      8  `' .oooo8 8    ' 8oP'       8   8    8 8    8 
8    8 8     8    8 8    . 8 `b.      8   8    8 8    8 
`YooP' 8     `YooP8 `YooP' 8  `o.     8   `YooP' `YooP'   
{Style.RESET_ALL}'''


def get_random_headers():
    ua = UserAgent()
    return {"User-Agent": ua.random}


def start_scan(session, domain, directory, output_file, timeout, allowed_status_code, lean_body, extensions, userAgent,
               verbose, quiet_mode):
    if not extensions:
        extensions = [""]

    headers = get_random_headers() if userAgent else {}

    for ext in extensions:
        url = f"http://{domain}/{directory}{'.' + ext}"
        try:
            if quiet_mode:
                time.sleep(random.uniform(1, 5))  # Медленный режим для обхода WAF

            response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)

            if response.status_code in allowed_status_code:
                body_length = len(response.text) if lean_body else " "
                color = Fore.RED if response.status_code // 100 in [4, 5] else Fore.GREEN
                if verbose:
                    message = f"{color}[{response.status_code}]  /{directory}{'.' + ext}  {url}  {body_length} {response.headers}{Style.RESET_ALL}\n"

                    safe_print(message)
                else:
                    message = f"{color}[{response.status_code}]  /{directory}{'.' + ext}  {url}  {body_length}{Style.RESET_ALL}"

                    safe_print(message)

                with open(output_file, "a") as file:
                    file.write(f"{url} | {response.status_code}\n")

        except requests.ConnectionError:
            pass


def parse_status_codes(status_code):
    try:
        return set(map(int, status_code.split(','))) if status_code else {200}
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid status code values{Style.RESET_ALL}")
        return {200}


def measure_time(func, *args):
    start_time = time.time()
    func(*args)
    elapsed_time = time.time() - start_time
    print()
    print(f"{Fore.YELLOW}[*] End Time: [{time.strftime('%H:%M:%S')}]\n[*] Scan completed in {int(elapsed_time // 60)}m {int(elapsed_time % 60)}s{Style.RESET_ALL}")


def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Directory Scanner")
    parser.add_argument("host", type=str, help="Target domain (e.g., example.com)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Max concurrent threads (default: 20. Example: -t 30)")
    parser.add_argument("-ua", "--user-agent", action='store_true', help="Use random User-Agents")
    parser.add_argument("-i", "--input", type=str, required=True, help="Path to directories wordlist")
    parser.add_argument("-o", "--output", type=str, required=False, help="File to save scan results (Example: -o result.txt)")
    parser.add_argument("-time", "--timeout", type=int, default=7, help="Request timeout (default: 7s. Example: -time 10)")
    parser.add_argument("-sc", "--status-code", type=str,  help="Comma-separated status codes to filter (Example: -t 200). Default value - 200")
    parser.add_argument("-lb", "--lean-body", action='store_true', help="Show response body length")
    parser.add_argument("-e", "--extensions", type=str, help="Comma-separated file extensions (Example: -e php,html,txt,js)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Verbose mode (show headers)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode for bypassing WAF")
    return parser.parse_args()


def run_scan(domain, directories, output, timeout, threads, allowed_status_code, lean_body, extensions, useragent,
             verbose, quiet_mode):
    extensions = extensions.split(',') if extensions else ''
    threads = random.randint(1, 5) if quiet_mode else threads  # Ограничиваем потоки в тихом режиме

    session = requests.Session()
    if cloudscraper:
        session = cloudscraper.create_scraper()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(start_scan, session, domain, directory, output, timeout, allowed_status_code, lean_body,
                            extensions, useragent, verbose, quiet_mode)
            for directory in directories]
        concurrent.futures.wait(futures)


def main():
    args = parse_args()
    allowed_status_code = parse_status_codes(args.status_code)
    try:
        with open(args.input, "r") as file:
            directories = file.read().splitlines()
            if not directories:
                raise ValueError(f"{Fore.RED}[ERROR] Wordlist file is empty{Style.RESET_ALL}")
    except (FileNotFoundError, ValueError) as e:
        print(e)
        sys.exit(1)

    print(LOGO)
    print()
    print('#' * 50)
    print(f'{Fore.LIGHTRED_EX}[!] Summary Information:{Style.RESET_ALL}\n'
          f'{Fore.LIGHTWHITE_EX}Host: {args.host}\n'
          f'The total number of lines in the file {args.input}: {len(directories)}\n'
          f'Threads: {"1-5 (Quiet Mode)" if args.quiet else args.threads}\n'
          f'Timeout: {args.timeout}\n'
          f'Output: {args.output}\n'
          f'Extensions: {args.extensions}\n'
          f'Verbose mode: {args.verbose}\n'
          f'Quiet mode: {args.quiet}\n'
          f'Status Codes: {args.status_code}{Style.RESET_ALL}')
    print('#' * 50)
    print()
    print(f"{Fore.LIGHTMAGENTA_EX}-{Style.RESET_ALL}" * 50)
    print(f'{Fore.LIGHTMAGENTA_EX}| StatusCode | Directory | URL | BodyLength |{Style.RESET_ALL}')
    print(f"{Fore.LIGHTMAGENTA_EX}-{Style.RESET_ALL}" * 50)
    print(f"{Fore.YELLOW}[*] Starting Directory Scan...\n"
          f"[*] Launch Time: [{time.strftime('%H:%M:%S')}]{Style.RESET_ALL}")
    print()

    measure_time(run_scan, args.host, directories, args.output, args.timeout, args.threads, allowed_status_code,
                 args.lean_body, args.extensions, args.user_agent, args.verbose, args.quiet)


if __name__ == "__main__":
    main()
