import time
import requests
import statistics

API_URL = "http://127.0.0.1:5000/predict"
TEST_URLS = [
    "https://amazon.com",
    "https://google.com",
    "https://github.com",
]

def run_benchmark():
    latencies = []
    print("Starting latency benchmark...")
    
    # Check health
    try:
        health = requests.get("http://127.0.0.1:5000/health")
        if health.status_code != 200:
            print("API is not healthy. Exiting.")
            return
    except requests.exceptions.ConnectionError:
        print("API is not running. Start the backend first.")
        return

    for url in TEST_URLS:
        start_time = time.time()
        res = requests.post(API_URL, json={"url": url})
        end_time = time.time()
        
        latency = (end_time - start_time) * 1000
        latencies.append(latency)
        
        print(f"URL: {url} | Latency: {latency:.2f}ms | Status: {res.status_code}")

    if latencies:
        print("\n--- Benchmark Results ---")
        print(f"Mean Latency: {statistics.mean(latencies):.2f}ms")
        print(f"Median Latency: {statistics.median(latencies):.2f}ms")
        print(f"Min Latency: {min(latencies):.2f}ms")
        print(f"Max Latency: {max(latencies):.2f}ms")

if __name__ == '__main__':
    run_benchmark()
