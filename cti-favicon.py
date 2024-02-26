import mmh3
import requests
import json
import codecs
import shodan
from urllib.parse import urlparse
import socket

abuseipdb_api_key = ""
shodan_api_key = ""
ipdata_api_key = ""


log_info = {
    "total_shodan_ips": 0,
    "total_pages_processed": 0,
    "total_pages_skipped": 0,
}

ascii = r"""
  _   _   _____    ___    _   _   ___   _____    ___  
 | \ | | | ____|  / _ \  | \ | | |_ _| |_   _|  / _ \ 
 |  \| | |  _|   | | | | |  \| |  | |    | |   | | | |
 | |\  | | |___  | |_| | | |\  |  | |    | |   | |_| |
 |_| \_| |_____|  \___/  |_| \_| |___|   |_|    \___/ 
 Contact:                                                                                                                                                      
"""

def print_neonito():
    print(ascii)

def get_full_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return f"http://{url}"
    return url

def print_valid_ips(valid_ips):
    if valid_ips:
        print("Valid IPs:")
        for ip in valid_ips:
            print(f"    {ip}")
    else:
        print("No valid IPs found.")

def get_favicon_hash(url):
    try:
        favicon_url = f"{url}/favicon.ico"
        favicon_response = requests.get(favicon_url)
        favicon_response.raise_for_status()
        favicon_content = favicon_response.content
        favicon_hash = mmh3.hash(codecs.encode(favicon_content, "base64"))
        return favicon_hash
    except requests.exceptions.RequestException as e:
        print(f"Error fetching favicon for {url}: {e}")
        log_info["total_pages_skipped"] += 1
        return None

def get_internetdb_results(ip):
    try:
        result = requests.get(f"https://internetdb.shodan.io/{ip}").json()
        return result
    except requests.exceptions.RequestException as e:
        print(f"InternetDB Error: {e}")
        return None

def get_shodan_results(api_key, query):
    api = shodan.Shodan(api_key)
    try:
        results = api.search(query)
        return results
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        return None

def get_abuseipdb_details(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        "Key": abuseipdb_api_key,
        "Accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        abuseipdb_result = response.json()
        return {"abuseipdb_result": abuseipdb_result}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching AbuseIPDB data for {ip}: {e}")
        return {}

def get_ipdata_details(ip):
    url = f"https://api.ipdata.co/{ip}/threat?api-key={ipdata_api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        ipdata_result = response.json()
        threat_info = {
            "is_tor": ipdata_result.get("is_tor", False),
            "is_icloud_relay": ipdata_result.get("is_icloud_relay", False),
            "is_proxy": ipdata_result.get("is_proxy", False),
            "is_datacenter": ipdata_result.get("is_datacenter", False),
            "is_anonymous": ipdata_result.get("is_anonymous", False),
            "is_known_attacker": ipdata_result.get("is_known_attacker", False),
            "is_known_abuser": ipdata_result.get("is_known_abuser", False),
            "is_threat": ipdata_result.get("is_threat", False),
            "is_bogon": ipdata_result.get("is_bogon", False),
            "blocklists": [blocklist["name"] for blocklist in ipdata_result.get("blocklists", [])],
            "scores": ipdata_result.get("scores", {})
        }
        return {"threat": threat_info}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching IP data for {ip}: {e}")
        return {}

def process_pages(file_path):
    global log_info

    with open(file_path, 'r') as file:
        for line in file:
            page_url = line.strip()
            log_info["total_pages_processed"] += 1
            print(f"\nProcessing page: {page_url}")

            full_url = get_full_url(page_url)

            favicon_hash = get_favicon_hash(full_url)
            if favicon_hash is None:
                continue

            results = get_shodan_results(shodan_api_key, f"http.favicon.hash:{favicon_hash}")

            if results is not None:
                log_info["total_shodan_ips"] += len(results['matches'])
                print(f"Total Shodan IPs found: {log_info['total_shodan_ips']}")
                print(f"Total pages processed: {log_info['total_pages_processed']}")
                print(f"Total pages skipped: {log_info['total_pages_skipped']}")

                ip_port_info_list = [extract_shodan_info(match) for match in results['matches']]

                ipdata_results = []
                abuseipdb_results = []
                valid_ips = []
                for i, ip_port_info in enumerate(ip_port_info_list):
                    abuseipdb_result = get_abuseipdb_details(ip_port_info['ip'])
                    ipdata_result = get_ipdata_details(ip_port_info['ip'])
                    abuseipdb_results.append({
                        "shodan_result": ip_port_info,
                        "abuseipdb_result": abuseipdb_result,
                        "ipdata_result": ipdata_result
                    })

                    if check_ip(ip_port_info['ip']):
                        valid_ips.append(ip_port_info['ip'])

                add_log_info({"total_valid_ips": len(valid_ips)})
                add_log_info({"total_invalid_ips": len(ip_port_info_list) - len(valid_ips)})

                page_name = extract_domain_name(page_url)
                save_to_json(page_name, abuseipdb_results, valid_ips)
                print_valid_ips(valid_ips)

def extract_shodan_info(match):
    ip_port_info = {
        "ip": match.get('ip_str', ''),
        "port": match.get('port', 0),
        "header": match.get('data', '').splitlines()[0],
        "name": match.get('hostnames', [''])[0] if match.get('hostnames') else ''
    }
    return ip_port_info

def extract_domain_name(url):
    parsed_url = urlparse(url)
    domain_name = parsed_url.netloc
    domain_name = domain_name.replace('www.', '')
    domain_name = domain_name.replace('http://', '')
    domain_name = domain_name.replace('https://', '')
    domain_name = domain_name.replace('.', '')
    domain_name = domain_name.replace('/', '')
    domain_name = domain_name.replace('com', '')
    return domain_name

def save_to_json(page_name, data, valid_ips):
    with open(f"{page_name}-result.json", 'w') as json_file:
        result_data = {
            "Total Shodan IPs found": log_info["total_shodan_ips"],
            "Total pages processed": log_info["total_pages_processed"],
            "Total pages skipped": log_info["total_pages_skipped"],
            "Valid IPs": valid_ips,
            "Data": data
        }

        if log_info["total_invalid_ips"] != 0:
            result_data["Total Invalid IPs found"] = log_info["total_invalid_ips"]

        json.dump(result_data, json_file, indent=2)

def add_log_info(info):
    log_info.update(info)

def check_ip(ip):
    port = 80
    timeout = 2

    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error) as e:
        return False

def main():
    print_neonito()
    input_file = 'urls.txt'
    process_pages(input_file)

if __name__ == "__main__":
    main()
