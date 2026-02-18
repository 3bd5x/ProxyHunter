#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, time, threading, os, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from colorama import Fore, init
from ipwhois import IPWhois
import socks

init(autoreset=True)

TIMEOUT = 7
THREADS = 60
TEST_URL = "http://httpbin.org/ip"

working = []
lock = threading.Lock()
start_time = time.time()

# BANNER
def banner():
    print(Fore.GREEN + r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣶⠀⠀⢀⣄⠀⠀⣠⣶⣾⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⡛⣆⣰⣿⣿⣠⠞⣓⣿⣿⠶⠞⠛⣫⣿⣷⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⡥⣿⡏⣸⡿⠛⠉⠉⠉⠉⠉⠓⢲⣿⠿⢱⣿⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡴⠶⢿⡋⠀⠟⠛⠁⣀⣀⣀⠀⠀⠀⠺⡷⠚⠉⢀⣾⣿⣶⣿⠗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣷⣅⠙⠀⠀⢠⠞⢛⣿⣭⣙⠛⣦⡀⠹⣄⣀⡼⣻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⡏⣿⠀⠀⠀⢠⡞⠋⢹⡟⠟⢳⡈⢧⠀⠈⠙⠿⢻⠃⣷⠈⢻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣀⣸⡿⠿⠟⠲⠶⢤⣼⠀⢹⣿⠁⠀⢨⡇⠀⠀⠀⠀⠀⠉⠀⢿⣷⡾⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⡾⠹⠆⠀⠀⠀⠀⠀⠀⠈⠳⣼⣿⣷⣤⡾⠁⠀⠀⠀⠀⠀⠀⠀⣿⣏⠻⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠘⣧⣀⡀⠀⠀⠐⠓⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⣰⠃⠘⣧⠀⠀⠀⠀⢠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⢯⡉⠙⢦⣀⠀⠀⠀⠀⠀⢀⣰⠏⠀⠀⠀⠀⠀⠀⠀⠀⣶⣯⣤⢄⡿⠀⢀⣀⣠⣾⣏⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠹⢦⣀⣉⠒⠶⠶⠶⢶⣊⣡⣄⣀⣀⣀⣀⡤⠀⠀⠀⡿⠙⣯⣹⠷⣚⣋⣉⣡⡴⠟⢦⠈⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⠛⠉⠀⠀⢹⣯⠉⠁⢠⣄⡀⠀⢤⣤⣬⣿⣟⠉⠉⠁⢠⠀⠀⠀⢳⡸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⠀⠀⢺⡇⠙⢷⣽⣧⣠⣿⠿⢿⡉⠻⣾⣤⢤⣄⠀⣧⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⢀⡼⠁⠀⠀⠸⣇⢠⠘⢿⠙⢿⡏⠀⠈⠹⣄⠀⠀⠀⠈⢻⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣷⠞⠀⠀⠀⠀⠀⡇⢸⣿⢸⠀⠘⣏⠉⠳⢤⣘⣆⠀⠀⠀⠘⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠇⠀⠀⠀⠀⠀⠀⣧⣾⣾⡟⠀⠀⠙⣶⣶⡦⠿⠛⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣄⣤⡏⠀⠀⠀⠀⠀⠀⢰⣿⠟⠁⠀⠀⠀⠀⠛⣧⣀⡀⠀⠸⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⠛⢦⡀⠀⠀⠀⠀⣠⠞⠋⠉⠀⠈⣹⠃⠀⠀⠀⠀⠀⢠⡿⠋⠀⠀⠀⠀⠀⠀⠀⢻⣌⣙⢦⠀⠛⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣸⡇⠀⠀⠙⢦⠀⠀⣼⠇⠀⠀⠀⠀⠀⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⠋⠉⠁⠀⠈⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠀⢰⠻⡄⠈⢧⢰⡇⠀⠀⠀⠀⠀⠐⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡄⠀⠀⢠⠀⢸⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢿⣤⣾⠀⠻⢿⡛⠉⣇⠀⠀⠀⠀⠀⠀⠘⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡃⣹⡆⠀⠈⡇⢸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⠉⠸⣆⢀⣨⡻⣄⡸⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⠆⠀⠀⠀⠀⠀⠀⢰⡿⠛⠉⠀⠀⣸⠁⡾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢿⡄⠹⣿⣎⡹⢿⣦⡀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡴⠋⠁⠀⠀⠠⣿⡉⠉⢓⡾⠁⠀⠀⠀⢠⣿⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⢷⡀⠈⠳⣷⣴⣬⠉⠛⠛⠒⠲⠶⠚⠛⠋⠀⠀⢸⣿⠓⢤⡀⢸⣿⡴⠛⠀⠀⠀⠀⢠⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠹⣦⠀⠈⠛⠮⡇⣠⡟⠓⣆⠀⢸⠏⠛⢶⠀⣾⣿⡤⠼⠃⠀⠀⠀⠀⠀⠀⠀⣴⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠳⣤⡀⠀⠀⠉⠙⠓⠻⠀⠛⠛⠒⠚⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⡶⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠲⠦⢤⣤⣤⣤⣤⣤⣤⡶⠶⠚⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
""")
    print(Fore.BLUE + "PROXY & VPN Checker\n")
    print(Fore.BLUE + "Telegram: yagami0xx\n")


#FLAG 
def flag(code):
    if not code or len(code) != 2:
        return "🌍"
    return "".join(chr(0x1F1E6 + ord(c.upper()) - 65) for c in code)

# CONTINENT FIX 
def continent_from_country(code):
    continent_map = {
        "AF": "Africa",
        "AN": "Antarctica",
        "AS": "Asia",
        "EU": "Europe",
        "NA": "North America",
        "OC": "Oceania",
        "SA": "South America"
    }

    country_map = {
 # Asia
        "IQ":"AS","SA":"AS","AE":"AS","IR":"AS","TR":"AS","IN":"AS","CN":"AS","JP":"AS",
 # Europe
        "DE":"EU","FR":"EU","GB":"EU","IT":"EU","NL":"EU","ES":"EU","PL":"EU",
 # North America
        "US":"NA","CA":"NA","MX":"NA",
 # South America
        "BR":"SA","AR":"SA","CL":"SA",
 # Africa
        "EG":"AF","ZA":"AF","NG":"AF","DZ":"AF",
 # Oceania
        "AU":"OC","NZ":"OC"
    }

    if code in country_map:
        return continent_map[country_map[code]]

    return "Unknown"

# WHOIS 
def whois_lookup(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)

        return {
            "country": res.get("network", {}).get("country"),
            "asn": res.get("asn"),
            "org": res.get("network", {}).get("name")
        }
    except:
        return {}

# IP API
def api_lookup(ip):
    try:
        j = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,continent,as,org,isp",
            timeout=5
        ).json()
        if j.get("status") == "success":
            return {
                "country": j.get("countryCode"),
                "country_name": j.get("country"),
                "continent": j.get("continent"),
                "asn": j.get("as"),
                "org": j.get("org"),
                "isp": j.get("isp")
            }
    except:
        pass
    return {}

# MERGE DATA
def get_best_geo(ip):
    who = whois_lookup(ip)
    api = api_lookup(ip)

    country = api.get("country") or who.get("country") or "Unknown"
    country_name = api.get("country_name") or who.get("country") or "Unknown"

    asn = api.get("asn") or who.get("asn") or "Unknown"
    org = api.get("org") or who.get("org") or "Unknown"

    continent = api.get("continent")

 # FIX: fallback calculation
    if not continent or continent == "Unknown":
        continent = continent_from_country(country)

    return {
        "country": country,
        "country_name": country_name,
        "continent": continent,
        "asn": asn,
        "org": org
    }

# CLASSIFY 
def classify(asn, org, ptype):
    txt = f"{asn} {org}".lower()

    dc = ["digitalocean","ovh","hetzner","vultr","linode","amazon","aws","google","azure","oracle"]
    isp_kw = ["telecom","mobile","fiber","dsl","broadband","zain","orange","vodafone"]

    if any(k in txt for k in dc):
        return ("VPN / Datacenter", "HIGH" if ptype.startswith("SOCKS") else "MEDIUM")
    if any(k in txt for k in isp_kw):
        return ("Residential / ISP", "LOW")

    return ("Unknown / Mixed", "MEDIUM")

# DNS LEAK 
def dns_leak_test(ip, port, ptype):
    try:
        real = requests.get(TEST_URL, timeout=5).json()["origin"]

        if ptype == "SOCKS5":
            p = {"http": f"socks5h://{ip}:{port}", "https": f"socks5h://{ip}:{port}"}
        elif ptype == "SOCKS4":
            p = {"http": f"socks4://{ip}:{port}", "https": f"socks4://{ip}:{port}"}
        else:
            p = {"http": f"http://{ip}:{port}", "https": f"http://{ip}:{port}"}

        proxied = requests.get(TEST_URL, proxies=p, timeout=TIMEOUT).json()["origin"]
        return "NO" if proxied != real else "YES"
    except:
        return "UNKNOWN"

# CHECK PROXY
def check_proxy(proxy):
    try:
        ip, port = proxy.split(":")
        port = int(port)
    except:
        return

    detected = None
    latency = None

    for ptype in ("SOCKS5","SOCKS4","HTTP"):
        try:
            proxies = {
                "http": f"{ptype.lower()}://{ip}:{port}",
                "https": f"{ptype.lower()}://{ip}:{port}"
            }
            t0 = time.time()
            requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
            latency = int((time.time()-t0)*1000)
            detected = ptype
            break
        except:
            continue

    if not detected:
        print(Fore.RED + f"[-] {ip}:{port} DEAD")
        return

    geo = get_best_geo(ip)
    role, privacy = classify(geo["asn"], geo["org"], detected)

    data = {
        "ip": ip,
        "port": port,
        "type": detected,
        "latency": latency,
        "country": geo["country"],
        "country_name": geo["country_name"],
        "continent": geo["continent"],
        "flag": flag(geo["country"]),
        "asn": geo["asn"],
        "org": geo["org"],
        "role": role,
        "privacy": privacy,
        "dns": dns_leak_test(ip, port, detected)
    }

    with lock:
        working.append(data)

    print(Fore.GREEN + f"[+] {ip}:{port} {detected}")

# SOCKS5 TUNNEL 
def start_socks5_tunnel(proxy_ip, proxy_port):
    print(Fore.CYAN + "\nStarting SOCKS5 Tunnel on 127.0.0.1:1080")
    socks.set_default_proxy(socks.SOCKS5, proxy_ip, proxy_port)
    socket.socket = socks.socksocket
    print(Fore.GREEN + "Tunnel Active → 127.0.0.1:1080")
    print("Press CTRL+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nTunnel stopped.")

# MAIN
def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("  python3 proxy_checker.py proxies.txt")
        print("  python3 proxy_checker.py IP:PORT")
        return

    banner()
    target = sys.argv[1]

    if ":" in target and not os.path.isfile(target):
        proxies = [target]
    else:
        with open(target) as f:
            proxies = [x.strip() for x in f if ":" in x]

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for _ in as_completed([ex.submit(check_proxy, p) for p in proxies]):
            pass

    print(Fore.CYAN + f"\nScan finished in {int(time.time()-start_time)}s\n")

    for i, p in enumerate(working,1):
        print(f"""
[{i}] {p['ip']}:{p['port']}
    Type      : {p['type']}
    Role      : {p['role']}
    Privacy   : {p['privacy']}
    Country   : {p['country']} {p['flag']} ({p['country_name']})
    Continent : {p['continent']}
    Speed     : {p['latency']} ms
    DNS Leak  : {p['dns']}
    ASN / Org : {p['asn']} ({p['org']})
""")

    if not working:
        return

    try:
        ch = int(input("Choose proxy number to CONNECT (SOCKS5 only): "))
        if 1 <= ch <= len(working):
            if working[ch-1]["type"] == "SOCKS5":
                start_socks5_tunnel(working[ch-1]["ip"], working[ch-1]["port"])
            else:
                print("Tunnel works only with SOCKS5.")
    except:
        pass

if __name__ == "__main__":
    main()
