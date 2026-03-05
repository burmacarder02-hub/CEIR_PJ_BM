from flask import Flask, request, jsonify
import requests
import json
import base64
import hashlib
import time
import multiprocessing
import random
from typing import Optional, Tuple, List

app = Flask(__name__)

# ───────────────────────────────────────────────
# CEIR Myanmar ALTCHA + IMEI Verify Config - 2026
# ───────────────────────────────────────────────

CHALLENGE_URL = "https://ceir.gov.mm/openapi/API/Auth/altcha/altcha"
VERIFY_URL = "https://ceir.gov.mm/openapi/API/IMEI/Verify"

HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/json",
    "Origin": "https://ceir.gov.mm",
    "Referer": "https://ceir.gov.mm/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"'
}

# Sources that provide plain text lists of http proxies (ip:port format)
PROXY_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-List/main/proxies/http/data.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt",
]

PROXIES: List[str] = []  # global list, will be populated on startup

def fetch_fresh_proxies() -> List[str]:
    """Pull fresh proxies from multiple public sources"""
    collected = set()
    
    for source in PROXY_SOURCES:
        try:
            r = requests.get(source, timeout=8)
            if r.status_code != 200:
                continue
            lines = r.text.strip().splitlines()
            for line in lines:
                line = line.strip()
                if ':' in line and line.count('.') >= 3:  # rough ip:port check
                    collected.add(f"http://{line}")
        except Exception:
            pass  # silent fail, try next source
    
    # Convert to list and shuffle
    proxy_list = list(collected)
    random.shuffle(proxy_list)
    
    print(f"[Proxy fetch] Collected {len(proxy_list)} proxies")
    return proxy_list[:150]  # cap at 150 to avoid memory bloat

def get_random_proxy() -> dict | None:
    global PROXIES
    if not PROXIES:
        return None
    proxy = random.choice(PROXIES)
    return {"http": proxy, "https": proxy}

def request_with_proxy_retry(method: str, url: str, **kwargs):
    attempts = 0
    max_attempts = 6  # try 5 proxies + 1 direct

    while attempts < max_attempts:
        proxies = get_random_proxy()
        try:
            if method.upper() == 'GET':
                r = requests.get(url, headers=HEADERS, proxies=proxies, **kwargs)
            elif method.upper() == 'POST':
                r = requests.post(url, headers=HEADERS, proxies=proxies, **kwargs)
            else:
                raise ValueError("Unsupported method")

            r.raise_for_status()
            return r

        except Exception as e:
            attempts += 1
            proxy_str = proxies.get('http', 'direct') if proxies else 'direct'
            print(f"[Retry {attempts}/{max_attempts}] Failed with {proxy_str} → {str(e)[:80]}...")
            time.sleep(random.uniform(0.3, 1.2))  # random backoff

    raise Exception("All proxy attempts failed, even direct connection")

def fetch_challenge() -> dict:
    r = request_with_proxy_retry('GET', CHALLENGE_URL)
    return r.json()

def solve_pow_worker(args: Tuple[str, str, int, int]) -> Optional[int]:
    salt, challenge, start, end = args
    for number in range(start, end + 1):
        input_str = salt + str(number)
        hash_hex = hashlib.sha256(input_str.encode('utf-8')).hexdigest()
        if hash_hex == challenge:
            return number
    return None

def solve_pow(salt: str, challenge: str, maxnumber: int) -> Tuple[int, int]:
    start_time = time.time()
    workers = multiprocessing.cpu_count()
    chunk_size = (maxnumber + 1) // workers
    ranges = [(salt, challenge, i * chunk_size, min((i + 1) * chunk_size - 1, maxnumber)) for i in range(workers)]
    
    with multiprocessing.Pool(processes=workers) as pool:
        results = pool.map(solve_pow_worker, ranges)
    
    number = next((res for res in results if res is not None), None)
    if number is None:
        raise ValueError("No nonce found — challenge likely expired")
   
    took_ms = int((time.time() - start_time) * 1000)
    return number, took_ms

def build_altcha_token(challenge_data: dict, number: int, took: int) -> str:
    payload = {
        "algorithm": challenge_data["algorithm"],
        "challenge": challenge_data["challenge"],
        "number": number,
        "salt": challenge_data["salt"],
        "signature": challenge_data["signature"],
        "took": took
    }
    json_str = json.dumps(payload, separators=(',', ':'))
    return base64.b64encode(json_str.encode('utf-8')).decode('utf-8')

def verify_imei(imei: str, altcha: str) -> dict:
    url = f"{VERIFY_URL}?altcha={altcha}"
    payload = [imei]
    r = request_with_proxy_retry('POST', url, data=json.dumps(payload))
    return r.json()

# ───────────────────────────────────────────────
# Flask Routes
# ───────────────────────────────────────────────

@app.route('/check', methods=['GET'])
def check_imei():
    imei = request.args.get('imei')
    if not imei or not imei.isdigit() or len(imei) != 15:
        return jsonify({"error": "Invalid or missing IMEI (must be 15 digits)"}), 400
    
    try:
        challenge_data = fetch_challenge()
        number, took = solve_pow(
            salt=challenge_data["salt"],
            challenge=challenge_data["challenge"],
            maxnumber=challenge_data["maxnumber"]
        )
        altcha = build_altcha_token(challenge_data, number, took)
        result = verify_imei(imei, altcha)
        
        return jsonify({
            "status": "success",
            "imei": imei,
            "altcha_number": number,
            "took_ms": took,
            "ceir_result": result
        })
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "imei": imei
        }), 500

@app.route('/')
def home():
    return f"""
    <h1>CEIR IMEI Checker API</h1>
    <p>Use: <code>http://127.0.0.1:5000/check?imei=865163040845331</code></p>
    <p>Proxies loaded: {len(PROXIES)}</p>
    """

if __name__ == '__main__':
    # Fetch fresh proxies on startup
    PROXIES = fetch_fresh_proxies()
    
    # Optional: refresh every 30 minutes (uncomment if running long-term)
    # import threading
    # def refresh_proxies_periodically():
    #     global PROXIES
    #     while True:
    #         time.sleep(1800)
    #         PROXIES = fetch_fresh_proxies()
    # threading.Thread(target=refresh_proxies_periodically, daemon=True).start()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
