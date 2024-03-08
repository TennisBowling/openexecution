import requests

# Define the URL
url = "http://192.168.1.10:8899"

# Define the JSON payload
payload = [
    {
        "jsonrpc": "2.0",
        "method": "eth_syncing",
        "params": [],
        "id": 1
    },
    {
        "jsonrpc": "2.0",
        "method": "eth_syncing",
        "params": [],
        "id": 1
    }
]

# Make the POST request
response = requests.post(url, json=payload)

# Print the response from the server
print(response.text)
