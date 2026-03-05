from flask import Flask, request, jsonify
import requests
import json
import base64
import hashlib
import time
import multiprocessing
from typing import Optional, Tuple

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

def fetch_challenge() -> dict:
    r = requests.get(CHALLENGE_URL, headers=HEADERS, timeout=10)
    r.raise_for_status()
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
    r = requests.post(url, headers=HEADERS, data=json.dumps(payload), timeout=15)
    r.raise_for_status()
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
    return """
    <h1>CEIR IMEI Checker API (localhost)</h1>
    <p>Use: <code>http://127.0.0.1:5000/check?imei=865163040845331</code></p>
    <p>Returns full CEIR response in JSON</p>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
