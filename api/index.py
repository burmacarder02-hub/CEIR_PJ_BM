from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
import requests
import json
import base64
import hashlib
import time
import multiprocessing
from typing import Tuple, Optional

app = FastAPI(title="CEIR Myanmar IMEI Checker API")

CHALLENGE_URL = "https://ceir.gov.mm/openapi/API/Auth/altcha/altcha"
VERIFY_URL = "https://ceir.gov.mm/openapi/API/IMEI/Verify"

HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/json",
    "Origin": "https://ceir.gov.mm",
    "Referer": "https://ceir.gov.mm/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
}

def fetch_challenge() -> dict:
    r = requests.get(CHALLENGE_URL, headers=HEADERS, timeout=12)
    r.raise_for_status()
    return r.json()

def solve_pow_worker(args: Tuple[str, str, int, int]) -> Optional[int]:
    salt, challenge, start, end = args
    for number in range(start, end + 1):
        if hashlib.sha256((salt + str(number)).encode()).hexdigest() == challenge:
            return number
    return None

def solve_pow(salt: str, challenge: str, maxnumber: int) -> Tuple[int, int]:
    start_time = time.time()
    workers = max(2, multiprocessing.cpu_count() // 2)  # Vercel has limited CPU
    chunk = (maxnumber + 1) // workers
    ranges = [(salt, challenge, i*chunk, min((i+1)*chunk-1, maxnumber)) for i in range(workers)]

    with multiprocessing.Pool(workers) as pool:
        results = pool.map(solve_pow_worker, ranges)

    number = next((x for x in results if x is not None), None)
    if number is None:
        raise ValueError("PoW failed - challenge likely expired")
    
    took = int((time.time() - start_time) * 1000)
    return number, took

def build_altcha(challenge_data: dict, number: int, took: int) -> str:
    payload = {
        "algorithm": challenge_data["algorithm"],
        "challenge": challenge_data["challenge"],
        "number": number,
        "salt": challenge_data["salt"],
        "signature": challenge_data["signature"],
        "took": took
    }
    return base64.b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode()

def verify_imei(imei: str, altcha: str) -> dict:
    url = f"{VERIFY_URL}?altcha={altcha}"
    payload = [imei]
    r = requests.post(url, headers=HEADERS, json=payload, timeout=15)
    r.raise_for_status()
    return r.json()

@app.get("/check")
async def check(imei: str = Query(..., description="15-digit IMEI")):
    if not imei.isdigit() or len(imei) != 15:
        raise HTTPException(400, detail="IMEI must be exactly 15 digits")

    try:
        chall = fetch_challenge()
        number, took = solve_pow(chall["salt"], chall["challenge"], chall["maxnumber"])
        altcha_token = build_altcha(chall, number, took)
        result = verify_imei(imei, altcha_token)

        return {
            "status": "success",
            "imei": imei,
            "solved_number": number,
            "took_ms": took,
            "ceir_response": result
        }
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@app.get("/")
async def root():
    return {"message": "CEIR IMEI Checker API - use /check?imei=xxxxxxxxxxxxxxx"}