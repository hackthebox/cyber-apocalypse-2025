import requests

BASE_URL = "http://127.0.0.1:1337"  # Change this if hosted elsewhere

payload = "{{ 7 * 7 }}"

response = requests.post(f"{BASE_URL}/battle-report", data={
    "damage_dealt": payload
})

print(response.text)