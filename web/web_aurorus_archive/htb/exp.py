import requests

url = "http://127.0.0.1:1337/api/auctions/1/bids"
headers = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Cookie": "connect.sid=s%3ASSKDlckd5cT20K2oXrpvIPx3LzYn0Gj-.3bs%2FM%2FqSHXBXtOEh5PA%2FkhSavMCEvzUdsPQhTWhk3mc"
}

with open("words.txt") as f:
    for line in f:
        bid_value = line.strip()
        if not bid_value:
            continue
        data = {"bid": bid_value}
        r = requests.post(url, json=data, headers=headers)
        print(f"Sent bid '{bid_value}' -> Status: {r.status_code}")
