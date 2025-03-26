default: release

release:
	@echo "[*] Copying files..."
	@mkdir -p stoneforges_domain/challenge
	
	@cp -r challenge/application stoneforges_domain/challenge
	@cp -r config stoneforges_domain
	
	@cp release/Dockerfile stoneforges_domain/
	@cp release/build_docker.sh stoneforges_domain/
	@line_num=$$(grep -n ':socat' config/supervisord.conf | cut -d: -f1); \
 	sed -e "$${line_num},\$$s/^/;/g" config/supervisord.conf > release/supervisord.conf
	@cp release/supervisord.conf stoneforges_domain/config

	@echo "HTB{FAKE_FLAG_FOR_TESTING}" > stoneforges_domain/challenge/flag.txt
	@echo "IyEvYmluL2Jhc2gKc3VwZXJ2aXNvcmN0bCAtYyAvZXRjL3N1cGVydmlzb3Ivc3VwZXJ2aXNvcmQuY29uZiByZXN0YXJ0IG5naW54" | base64 -d > stoneforges_domain/challenge/restart_nginx.sh
	@echo "[+] Done copying files!"

	@echo "[*] Readying release..."
	@chmod +x stoneforges_domain/build_docker.sh
	@echo "[+] Done readying release"

	@echo "[*] Zipping folder..."
	@zip -9 -P hackthebox -r stoneforges_domain.zip stoneforges_domain/ > /dev/null
	@rm -rf stoneforges_domain
	@echo "[+] Done zipping folder!"

	@echo "[*] Cleaning up"
	@rm -f release/stoneforges_domain.zip
	@mv stoneforges_domain.zip release/
	@echo "[+] Done cleaning up"

.PHONY: default release