default: release

release:
	@echo "[*] Copying files..."
	@mkdir -p lyras_tavern/challenge
	
	@cp -r challenge/application lyras_tavern/challenge
	@cp -r config lyras_tavern
	
	@cp release/Dockerfile lyras_tavern/
	@cp release/build_docker.sh lyras_tavern/
	@line_num=$$(grep -n ':socat' config/supervisord.conf | cut -d: -f1); \
 	sed -e "$${line_num},\$$s/^/;/g" config/supervisord.conf > release/supervisord.conf
	@cp release/supervisord.conf lyras_tavern/config

	@echo "HTB{FAKE_FLAG_FOR_TESTING}" > lyras_tavern/challenge/flag.txt
	@echo "[+] Done copying files!"

	@echo "[*] Readying release..."
	@chmod +x lyras_tavern/build_docker.sh
	@echo "[+] Done readying release"

	@echo "[*] Zipping folder..."
	@zip -9 -P hackthebox -r lyras_tavern.zip lyras_tavern/ > /dev/null
	@rm -rf lyras_tavern
	@echo "[+] Done zipping folder!"

	@echo "[*] Cleaning up"
	@rm -f release/lyras_tavern.zip
	@mv lyras_tavern.zip release/
	@echo "[+] Done cleaning up"

.PHONY: default release