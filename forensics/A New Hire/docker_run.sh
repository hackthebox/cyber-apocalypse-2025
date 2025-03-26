docker build -t ca2025_webdav . $@
docker run --rm -p 12345:80 ca2025_webdav
