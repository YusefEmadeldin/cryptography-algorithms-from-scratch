import requests
import concurrent.futures
import time

BASE_URL = "http://127.0.0.1:5000/api"

def test_concurrency():
    print("--- Scenario 1: 1000 Concurrent Operations ---")
    def fetch_md5():
        try:
            res = requests.post(f"{BASE_URL}/md5", json={"message": "test"}, timeout=5)
            return res.status_code
        except Exception as e:
            return str(e)

    start_time = time.time()
    success_count = 0
    error_count = 0
    
    # Using 1000 concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(fetch_md5) for _ in range(1000)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result == 200:
                success_count += 1
            else:
                error_count += 1

    print(f"Time taken: {time.time() - start_time:.2f}s")
    print(f"Success (200 OK): {success_count}")
    print(f"Errors: {error_count}\n")

def test_null_input():
    print("--- Scenario 2: Null Input ---")
    # Sending missing fields that expect integers
    # app.py: q = int(request.json.get('q', 23)) - if we send q: null, get('q', 23) returns None, int(None) throws TypeError
    try:
        res = requests.post(f"{BASE_URL}/elgamal/keygen", json={"q": None, "alpha": None})
        print(f"Status Code: {res.status_code}")
        if res.status_code == 500:
            print("Result: Server crashed (500 Internal Server Error) - Not graceful.")
        else:
            print(f"Result: {res.text[:100]}")
    except Exception as e:
        print(f"Error: {e}")
    print()

def test_corrupted_ciphertext():
    print("--- Scenario 3: Corrupted Ciphertext ---")
    # Sending an invalid ECC point
    # C1=(999,999) C2=(999,999)
    payload = {
        "a": 2, "b": 3, "p": 97, "gx": 3, "gy": 6, "d": 5, "n": 100,
        "ciphertext": [
            {"C1": {"x": "999", "y": "999"}, "C2": {"x": "999", "y": "999"}}
        ]
    }
    try:
        res = requests.post(f"{BASE_URL}/ecc/decrypt", json=payload)
        print(f"Status Code: {res.status_code}")
        print(f"Result (Plaintext): {res.json().get('plaintext', 'No plaintext returned')}")
        print("Note: Outputting garbled text instead of crashing is considered a graceful failure in this context.")
    except Exception as e:
        print(f"Error: {e}")
    print()

def test_replay_attack():
    print("--- Scenario 4: Replay Attack Simulation ---")
    print("Simulating intercepting a valid hash request and replaying it.")
    payload = {"message": "transfer $100"}
    nonce = str(time.time())
    headers = {"X-Nonce": nonce, "X-Timestamp": str(int(time.time() * 1000))}
    
    res1 = requests.post(f"{BASE_URL}/md5", json=payload, headers=headers)
    print(f"Original Request Status: {res1.status_code}, Hash: {res1.json().get('hash')}")
    
    # Replay
    res2 = requests.post(f"{BASE_URL}/md5", json=payload, headers=headers)
    print(f"Replayed Request Status: {res2.status_code}, Hash: {res2.json().get('hash')}")
    if res1.json().get('hash') == res2.json().get('hash') and res1.status_code == 200:
        print("Result: Attack NOT rejected. The server is stateless and processes the replay identically.")
    else:
        print(f"Result: Attack rejected/detected. Status code: {res2.status_code}")
    print()

if __name__ == "__main__":
    test_concurrency()
    test_null_input()
    test_corrupted_ciphertext()
    test_replay_attack()
