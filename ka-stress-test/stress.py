#!/usr/bin/env python3
import argparse
import concurrent.futures
import requests
import time
import statistics
import random
import string
import re
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def generate_random_string(length=10):
    """Generate a random alphanumeric string of specified length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_padding(length):
    """Generate a padding string of specified length using [a-zA-Z0-9,.+-] characters."""
    padding_chars = string.ascii_letters + string.digits + ",.+-"
    return ''.join(random.choices(padding_chars, k=length))

def process_fuzz_and_padding(text):
    """Process a string to replace FUZZ and PADDING patterns."""
    if text is None:
        return None
        
    # Replace "FUZZ" with a random string
    while "FUZZ" in text:
        random_str = generate_random_string()
        text = text.replace("FUZZ", random_str, 1)
    
    # Replace "PADDING:X" with random padding of length X
    padding_pattern = re.compile(r'PADDING:(\d+)')
    match = padding_pattern.search(text)
    while match:
        padding_length = int(match.group(1))
        padding = generate_padding(padding_length)
        # Replace only the first occurrence
        text = text.replace(match.group(0), padding, 1)
        # Look for next match
        match = padding_pattern.search(text)
        
    return text

def make_request(url, method, headers, data, verify_ssl, session=None):
    """Make a single HTTP request and return the response time."""
    # Process URL and data to replace FUZZ and PADDING patterns
    url = process_fuzz_and_padding(url)
    data = process_fuzz_and_padding(data)
    
    start_time = time.time()
    try:
        if session:
            response = session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                verify=verify_ssl,
                timeout=10
            )
        else:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                verify=verify_ssl,
                timeout=10
            )
        status_code = response.status_code
    except Exception as e:
        status_code = f"Error: {str(e)}"
        
    end_time = time.time()
    return {
        "response_time": end_time - start_time,
        "status_code": status_code
    }

def stress_test(url, num_threads, duration, method, headers, data, verify_ssl, use_session=False):
    """Run a stress test with multiple threads for a specific duration."""
    print(f"Starting stress test against {url}")
    print(f"Threads: {num_threads}, Duration: {duration} seconds")
    print(f"Method: {method}")
    if 'Host' in headers:
        print(f"Host header: {headers['Host']}")
    print(f"Connection mode: {'Session (keep-alive)' if use_session else 'New connection per request'}")
    
    start_time = time.time()
    end_time = start_time + duration
    requests_completed = 0
    response_times = []
    status_codes = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = set()
        
        # Create sessions for each thread if using session mode
        sessions = None
        if use_session:
            sessions = [requests.Session() for _ in range(num_threads)]
        
        thread_counter = 0
        
        # Keep submitting new tasks until time is up
        while time.time() < end_time:
            if len(futures) < num_threads:
                if use_session:
                    # Rotate through sessions for each thread
                    session = sessions[thread_counter % num_threads]
                    thread_counter += 1
                    future = executor.submit(make_request, url, method, headers, data, verify_ssl, session)
                else:
                    future = executor.submit(make_request, url, method, headers, data, verify_ssl)
                futures.add(future)
            
            # Check for completed futures
            done, futures = concurrent.futures.wait(
                futures, 
                timeout=0.1,
                return_when=concurrent.futures.FIRST_COMPLETED
            )
            
            for future in done:
                result = future.result()
                response_times.append(result["response_time"])
                
                status = result["status_code"]
                if status in status_codes:
                    status_codes[status] += 1
                else:
                    status_codes[status] = 1
                    
                requests_completed += 1
    
    actual_duration = time.time() - start_time
    
    # Calculate and print results
    print("\n--- Results ---")
    print(f"Total requests: {requests_completed}")
    print(f"Actual test duration: {actual_duration:.2f} seconds")
    print(f"Requests per second: {requests_completed / actual_duration:.2f}")
    
    if response_times:
        print(f"Min response time: {min(response_times):.4f} seconds")
        print(f"Max response time: {max(response_times):.4f} seconds")
        print(f"Avg response time: {statistics.mean(response_times):.4f} seconds")
        print(f"Median response time: {statistics.median(response_times):.4f} seconds")
    
    print("\nStatus Code Distribution:")
    for status, count in status_codes.items():
        print(f"  {status}: {count} ({count/requests_completed*100:.1f}%)")

def main():
    parser = argparse.ArgumentParser(description="HTTP/HTTPS Stress Testing Tool")
    parser.add_argument("url", help="URL to test (use FUZZ for random strings or PADDING:X for X-length random padding)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Test duration in seconds (default: 10)")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--headers", help="HTTP headers in JSON format")
    parser.add_argument("--host", help="Value for the Host header")
    parser.add_argument("--data", help="Request body data (supports FUZZ and PADDING:X patterns)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--session", action="store_true", help="Use persistent connections (keep-alive) for requests")
    
    args = parser.parse_args()
    
    # Parse headers if provided
    headers = {}
    if args.headers:
        import json
        try:
            headers = json.loads(args.headers)
        except json.JSONDecodeError:
            print("Error: Invalid JSON format for headers")
            return
    
    # Add Host header if provided
    if args.host:
        headers['Host'] = args.host
    
    # make a test request before starting the stress test
    response = make_request(
        url=args.url,
        method=args.method.upper(),
        headers=headers,
        data=args.data,
        verify_ssl=not args.no_verify
    )
    print(f"Test request response time: {response['response_time']:.4f} seconds")
    print(f"Test request status code: {response['status_code']}")

    #return

    stress_test(
        url=args.url,
        num_threads=args.threads,
        duration=args.duration,
        method=args.method.upper(),
        headers=headers,
        data=args.data,
        verify_ssl=not args.no_verify,
        use_session=args.session
    )

if __name__ == "__main__":
    main()