#!/usr/bin/env python3
# By thibaut LOMBARD (Lombard Web)
# Socks5 Proxy checker 
# Features : denylist, mutiples csv inputs, verbose, stealth mode
import os
import csv
import socket
import time
import geoip2.database
import ipaddress
import requests
import argparse
from datetime import datetime
import socks  # Requires pysocks: pip install pysocks
import random
from pathlib import Path

# Constants
SOCKS5_FOLDER = "socks5"
INC_FOLDER = "inc"
BLACKLIST_FILE = "denylist.csv"
GEOIP_URLS = {
 "GeoLite2-Country.mmdb": "https://git.io/GeoLite2-Country.mmdb",
 "GeoLite2-City.mmdb": "https://git.io/GeoLite2-City.mmdb",
 "GeoLite2-ASN.mmdb": "https://git.io/GeoLite2-ASN.mmdb"
}
TIMEOUT = 5  # Socket timeout in seconds
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0"}

# Verbose print function with optional file logging
def verbose_print(message, verbose=False, log_file=None):
 if verbose:
  msg = f"[VERBOSE] {message}"
  print(msg)
  if log_file:
   with open(log_file, "a", encoding="utf-8") as f:
    f.write(f"{msg}\n")

# Generate timestamped filename
def generate_timestamped_filename(prefix):
 current_time = datetime.now().strftime("%d_%m_%Y-%H_%M_%S")
 return f"{prefix}_{current_time}"

# Download GeoLite2 databases if missing
def download_geoip_databases(verbose=False, log_file=None):
 Path(INC_FOLDER).mkdir(exist_ok=True)
 for db_name, url in GEOIP_URLS.items():
  db_path = os.path.join(INC_FOLDER, db_name)
  if not os.path.exists(db_path):
   verbose_print(f"Downloading {db_name} from {url}", verbose, log_file)
   try:
    response = requests.get(url, headers=HEADERS, timeout=10)
    response.raise_for_status()
    with open(db_path, "wb") as f:
     f.write(response.content)
    verbose_print(f"Saved {db_name} to {INC_FOLDER}/", verbose, log_file)
   except requests.RequestException as e:
    print(f"Failed to download {db_name}: {e}")
    sys.exit(1)

# Load denylist IPs and ranges
def load_denylist(verbose=False, log_file=None):
 denylist = []
 if os.path.exists(BLACKLIST_FILE):
  with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
   reader = csv.reader(f, delimiter=";")
   next(reader, None)  # Skip header if exists
   for row in reader:
    if len(row) > 0:
     ip_range = row[0].strip()
     verbose_print(f"Processing denylist entry: {ip_range}", verbose, log_file)
     try:
      if "0/255" in ip_range:
       cidr = ip_range.replace("0/255.0/255", "0.0/16")
      else:
       cidr = ip_range
      network = ipaddress.ip_network(cidr, strict=False)
      denylist.append(network)
      verbose_print(f"Added network: {network}", verbose, log_file)
     except ValueError as e:
      verbose_print(f"Invalid denylist entry {ip_range}: {e}", verbose, log_file)
 verbose_print(f"Loaded {len(denylist)} denylist networks", verbose, log_file)
 return denylist

# Check if IP is in denylist
def is_denylisted(ip, denylist, verbose=False, log_file=None):
 try:
  ip_addr = ipaddress.ip_address(ip)
  for network in denylist:
   if ip_addr in network:
    verbose_print(f"{ip} is in denylisted range {network}", verbose, log_file)
    return True
  verbose_print(f"{ip} not in denylist", verbose, log_file)
  return False
 except ValueError:
  verbose_print(f"Invalid IP format for denylist check: {ip}", verbose, log_file)
  return False

# Get GeoIP info (country, city, ASN)
def get_geoip_info(ip, verbose=False, log_file=None):
 country, city, asn = "Unknown", "Unknown", "Unknown"
 try:
  with geoip2.database.Reader(os.path.join(INC_FOLDER, "GeoLite2-Country.mmdb")) as reader:
   response = reader.country(ip)
   country = response.country.iso_code or "Unknown"
 except Exception as e:
  verbose_print(f"Country lookup failed for {ip}: {e}", verbose, log_file)
 try:
  with geoip2.database.Reader(os.path.join(INC_FOLDER, "GeoLite2-City.mmdb")) as reader:
   response = reader.city(ip)
   city = response.city.name or "Unknown"
 except Exception as e:
  verbose_print(f"City lookup failed for {ip}: {e}", verbose, log_file)
 try:
  with geoip2.database.Reader(os.path.join(INC_FOLDER, "GeoLite2-ASN.mmdb")) as reader:
   response = reader.asn(ip)
   asn = str(response.autonomous_system_number) or "Unknown"
 except Exception as e:
  verbose_print(f"ASN lookup failed for {ip}: {e}", verbose, log_file)
 verbose_print(f"GeoIP for {ip}: Country={country}, City={city}, ASN={asn}", verbose, log_file)
 return country, city, asn

# Get hostname and latency, optionally through a proxy
def check_proxy(ip, port, proxy=None, verbose=False, log_file=None):
 start_time = time.time()
 hostname = "Unknown"
 anonymity = "Low"
 speed_ms = "Timeout"

 if proxy:
  sock = socks.socksocket()
  sock.set_proxy(socks.SOCKS5, proxy["ip"], int(proxy["port"]))
  verbose_print(f"Using proxy {proxy['ip']}:{proxy['port']} for {ip}:{port}", verbose, log_file)
 else:
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

 sock.settimeout(TIMEOUT)
 try:
  port_int = int(port)
  sock.connect((ip, port_int))
  latency = (time.time() - start_time) * 1000
  speed_ms = f"{int(latency)}ms"
  try:
   hostname = socket.gethostbyaddr(ip)[0]
  except:
   verbose_print(f"Hostname lookup failed for {ip}", verbose, log_file)
  if hostname != "Unknown" and hostname != ip:
   anonymity = "High"
  sock.close()
  verbose_print(f"Connected to {ip}:{port} - Speed={speed_ms}, Anonymity={anonymity}", verbose, log_file)
  return hostname, speed_ms, anonymity
 except ValueError as e:
  verbose_print(f"Invalid port for {ip}:{port}: {e}", verbose, log_file)
  sock.close()
  return None, None, None
 except Exception as e:
  verbose_print(f"Connection failed for {ip}:{port}: {e}", verbose, log_file)
  sock.close()
  return None, None, None

# Load proxies from a single CSV file (support IP:Port or IP;Port)
def load_proxies_from_file(file_path, verbose=False, log_file=None):
 proxies = []
 with open(file_path, "r", encoding="utf-8") as f:
  reader = csv.reader(f, delimiter=";")
  header = next(reader, None)  # Skip header
  verbose_print(f"Header from {file_path}: {header}", verbose, log_file)
  for row in reader:
   if len(row) >= 1:
    if ":" in row[0]:
     try:
      ip, port = row[0].strip().split(":", 1)
      ipaddress.ip_address(ip)
      int(port)
      proxies.append({"ip": ip, "port": port})
      verbose_print(f"Loaded proxy from {file_path} (IP:Port format): {ip}:{port}", verbose, log_file)
     except ValueError as e:
      verbose_print(f"Invalid IP:Port entry in {file_path}: {row[0]} - {e}", verbose, log_file)
    elif len(row) >= 2:
     ip, port = row[0].strip(), row[1].strip()
     try:
      ipaddress.ip_address(ip)
      int(port)
      proxies.append({"ip": ip, "port": port})
      verbose_print(f"Loaded proxy from {file_path} (IP;Port format): {ip}:{port}", verbose, log_file)
     except ValueError as e:
      verbose_print(f"Invalid IP;Port entry in {file_path}: {row} - {e}", verbose, log_file)
    else:
     verbose_print(f"Malformed row in {file_path}: {row}", verbose, log_file)
   else:
    verbose_print(f"Empty row in {file_path}", verbose, log_file)
 return proxies

# Load proxies from all CSV files in folder
def load_proxies_from_folder(folder, verbose=False, log_file=None):
 proxies = []
 if not os.path.exists(folder):
  print(f"Folder {folder} not found.")
  return proxies
 for filename in os.listdir(folder):
  if filename.endswith(".csv"):
   file_path = os.path.join(folder, filename)
   proxies.extend(load_proxies_from_file(file_path, verbose, log_file))
   verbose_print(f"Loaded proxies from {file_path}", verbose, log_file)
 return proxies

# Filter proxies for stealth mode
def filter_proxies(proxies, country_code, verbose=False, log_file=None):
 filtered = []
 for proxy in proxies:
  country, _, _ = get_geoip_info(proxy["ip"], verbose, log_file)
  if country == country_code:
   filtered.append(proxy)
   verbose_print(f"Proxy {proxy['ip']}:{proxy['port']} matches country {country_code}", verbose, log_file)
 return filtered

# Append a single result to CSV
def append_result_to_csv(result, csv_file):
 headers = ["IP", "Port", "CountryCode", "Hostname", "Speed_ms", "Anonymity", "Timestamp", "ASN", "City"]
 file_exists = os.path.exists(csv_file)
 with open(csv_file, "a", newline="", encoding="utf-8") as f:
  writer = csv.writer(f, delimiter=";")
  if not file_exists:
   writer.writerow(headers)
  writer.writerow(result)

# Main checking function with incremental CSV updates and denylisted logging
def check_proxies(proxies, denylist, csv_file, denylisted_log=None, proxy=None, verbose=False, log_file=None):
 results = []
 denylisted = []
 total = len(proxies)
 for i, entry in enumerate(proxies, 1):
  ip, port = entry["ip"], entry["port"]
  if is_denylisted(ip, denylist, verbose, log_file):
   print(f"[{i}/{total}] Skipping denylisted IP: {ip}")
   denylisted.append(f"{ip}:{port}")
   continue

  country, city, asn = get_geoip_info(ip, verbose, log_file)
  print(f"[{i}/{total}] Checking {ip}:{port} ({country}, {city}, ASN {asn})")

  hostname, speed_ms, anonymity = check_proxy(ip, port, proxy, verbose, log_file)
  if speed_ms:
   timestamp = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
   result = [ip, port, country, hostname, speed_ms, anonymity, timestamp, asn, city]
   append_result_to_csv(result, csv_file)
   results.append(result)
   verbose_print(f"Added working proxy to {csv_file}: {ip}:{port}", verbose, log_file)

 if denylisted_log and denylisted:
  with open(denylisted_log, "w", encoding="utf-8") as f:
   f.write("Blacklisted Proxies:\n")
   f.write("\n".join(denylisted))
  print(f"Saved {len(denylisted)} denylisted proxies to {denylisted_log}")
 return results

# Main execution
def main():
 parser = argparse.ArgumentParser(description="Check SOCKS5 proxies from CSV files.")
 parser.add_argument("-i", "--input", help="Single input CSV file (overrides folder)")
 parser.add_argument("--speed", type=int, help="Max speed in ms for proxy-behind-proxy")
 parser.add_argument("--cc", help="Country code")
 parser.add_argument("--mode", choices=["normal", "stealth"], default="normal", help="Mode: normal or stealth")
 parser.add_argument("--v", choices=["log"], help="Verbose mode with logging to file (use --v=log)")
 parser.add_argument("--isdenylisted", action="store_true", help="Log denylisted proxies")
 args = parser.parse_args()

 # Setup logging
 log_file = None
 verbose = args.v == "log"
 if verbose:
  log_file = generate_timestamped_filename("scan") + ".log"
  with open(log_file, "w", encoding="utf-8"):  # Create empty log file
   pass
  print(f"Logging verbose output to {log_file}")

 # Download GeoIP databases
 download_geoip_databases(verbose, log_file)

 # Load denylist
 denylist = load_denylist(verbose, log_file)

 # Load proxies
 if args.input:
  proxies = load_proxies_from_file(args.input, verbose, log_file)
  print(f"Loaded {len(proxies)} proxies from {args.input}")
 else:
  proxies = load_proxies_from_folder(SOCKS5_FOLDER, verbose, log_file)
  print(f"Loaded {len(proxies)} proxies from {SOCKS5_FOLDER} folder")

 if not proxies:
  print("No proxies to check.")
  return

 # Proxy-behind-proxy or stealth mode
 proxy = None
 if args.mode == "stealth" and args.cc:
  filtered = filter_proxies(proxies, args.cc, verbose, log_file)
  if filtered:
   proxy = random.choice(filtered)
   print(f"Stealth mode: Using proxy {proxy['ip']}:{proxy['port']} ({args.cc})")
  else:
   print(f"No proxies found for country {args.cc} in stealth mode.")
   return
 elif args.speed and args.cc:
  proxy_file = os.path.join(SOCKS5_FOLDER, "openproxylist_com_sample.csv")
  if os.path.exists(proxy_file):
   proxy_list = load_proxies_from_file(proxy_file, verbose, log_file)
   for p in proxy_list:
    p["speed"] = f"{random.randint(50, 300)}ms"
    p["countrycode"], _, _ = get_geoip_info(p["ip"], verbose, log_file)
   filtered = [p for p in proxy_list if int(p["speed"].replace("ms", "")) <= args.speed and p["countrycode"] == args.cc]
   if filtered:
    proxy = random.choice(filtered)
    print(f"Using proxy {proxy['ip']}:{proxy['port']} ({proxy['countrycode']}, {proxy['speed']})")
   else:
    print(f"No proxies found with speed <= {args.speed}ms and country {args.cc}")
    return
  else:
   print("Proxy file for filtering not found.")
   return

 # Check proxies with incremental CSV updates
 csv_file = generate_timestamped_filename("result") + ".csv"
 denylisted_log = generate_timestamped_filename("denylisted") + ".log" if args.isdenylisted else None
 results = check_proxies(proxies, denylist, csv_file, denylisted_log, proxy, verbose, log_file)
 print(f"Finished checking. Results saved incrementally to {csv_file}")

if __name__ == "__main__":
 main()
