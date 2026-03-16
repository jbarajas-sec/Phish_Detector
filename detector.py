import os, extract_msg, re, requests, time, urllib3, base64, urllib.parse
from dotenv import load_dotenv

# 1. Setup
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def log_threat(file_name, link, malicious_count, reason=""):
    try:
        with open("threat_log.txt", "a") as f:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] ALERT | {file_name} | {reason} | {malicious_count} hits | {link}\n")
    except: pass

def get_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def decode_wrapped_url(url):
    """Recursively peels Sophos and Mimecast layers."""
    current_url = url.replace("&amp;", "&")
    for _ in range(3): # Peels up to 3 layers deep
        try:
            p = urllib.parse.urlparse(current_url)
            qs = urllib.parse.parse_qs(p.query)
            # Sophos check
            if 'u' in qs:
                t = qs['u'][0]
                try:
                    padded = t + "=" * ((4 - len(t) % 4) % 4)
                    dec = base64.b64decode(padded).decode('utf-8', errors='ignore')
                    if "http" in dec: current_url = dec; continue
                except: pass
                current_url = t; continue
            # Mimecast check
            if 'url' in qs:
                current_url = qs['url'][0]; continue
            if 'domain' in qs: # Some variants hide the domain here
                current_url = "http://" + qs['domain'][0]; continue
        except: break
    return current_url

def triage_outlook_email(msg_path):
    try:
        msg = extract_msg.openMsg(msg_path)
        body = msg.body if msg.body else msg.htmlBody
        if not body: return
        if isinstance(body, bytes): body = body.decode('utf-8', errors='ignore')

        links = re.findall(r'https?://[^\s<>"]+', body)
        clean = [l for l in links if "schemas.microsoft.com" not in l]

        fname = os.path.basename(msg_path)
        print(f"\n--- [ ANALYSIS: {fname} ] ---")

        headers = {"x-apikey": API_KEY, "accept": "application/json"}

        for l in clean:
            real_l = decode_wrapped_url(l)
            # Get the domain for a secondary check
            domain = urllib.parse.urlparse(real_l).netloc
            
            print(f"\n[?] TARGET: {real_l[:75]}...")
            
            # 1. Check the specific URL
            url_id = get_url_id(real_l)
            res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, verify=False)
            
            # 2. Check the Domain Reputation (Bonus intelligence)
            dom_res = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, verify=False)
            
            malicious_found = False
            
            # Handle URL results
            if res.status_code == 200:
                stats = res.json()['data']['attributes']['last_analysis_stats']
                if stats['malicious'] > 0:
                    print(f"  !! ALERT: URL flagged by {stats['malicious']} vendors !!")
                    log_threat(fname, real_l, stats['malicious'], "URL_REPUTATION")
                    malicious_found = True

            # Handle Domain results (if URL was clean)
            if not malicious_found and dom_res.status_code == 200:
                d_stats = dom_res.json()['data']['attributes']['last_analysis_stats']
                if d_stats['malicious'] > 0:
                    print(f"  !! ALERT: Domain ({domain}) is flagged by {d_stats['malicious']} vendors !!")
                    log_threat(fname, domain, d_stats['malicious'], "DOMAIN_REPUTATION")
                    malicious_found = True

            if not malicious_found:
                if res.status_code == 404:
                    print("  [*] New URL. Submitting scan...")
                    requests.post("https://www.virustotal.com/api/v3/urls", data={"url": real_l}, headers=headers, verify=False)
                else:
                    print("  [OK] No immediate detections found.")
                    
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    folder = 'samples'
    if not os.path.exists(folder): os.makedirs(folder)
    msg_files = [f for f in os.listdir(folder) if f.lower().endswith('.msg')]
    for f in msg_files:
        triage_outlook_email(os.path.join(folder, f))
    input("\n[*] Complete. Press Enter...")