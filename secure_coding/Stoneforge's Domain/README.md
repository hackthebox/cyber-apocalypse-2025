![img](./assets/banner.png)

<img src='./assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Stoneforge's Domain</font>

5<sup>th</sup> February 2025

Prepared By: `Pyp`

Challenge Author(s): `Pyp`

Difficulty: <font color='green'>Easy</font>

<br><br>


# Synopsis
The challenge is a secure coding challenge targetting Nginx alias traversals modelling the [Nginx vulnerability article](https://hakaisecurity.io/nginx-alias-traversal/insights-blog/) that show cased path traversal by aliases within the Nginx configuration. By properly enumerating the server, we can be able to identify the vulnerability and patch it accordingly.

## Description
The challenge involves an internal Flask web server with a Nginx reverse proxy used to access it. The player is presented with 3 services available: 
- Nginx web server on internal port 3000 exposed on local port 80
- SMB services on both ports 445
- Checker service on both port 1337

The SMB service allows the user to easily enumerate the source code and make necessary changes on the server to ensure that the server works properly. 

The Nginx configuration file has a minor error that allows it to have limited directory traversal within its structure, but depending on the nature of the environment, further exploitation may see us achieving full arbitrary read on any systems. In our case, the exploit seems limited but that is not the full case.

## Skills Required
- Nginx configuration understanding.
- Basic Python code understanding.

## Skills Learned
- Proper Nginx configuration understanding
- Dockerfile code analysis.

# Enumeration

## Analyzing the source code and the report
Let us begin looking at the Dockerfile:
```dockerfile
# Copy the configuration files
COPY --chmod=646 config/nginx.conf /etc/nginx/nginx.conf
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/samba.conf /etc/samba/smb.conf
COPY config/postgresql.conf /etc/postgresql/17/main/postgresql.conf
```
- From the above, we notice that the `nginx.conf` has read and write permissions for the `everyone` group. This immediately points us to look at the `nginx.conf`:
```conf
user www-data;
pid /run/nginx.pid;
error_log /dev/stderr info;

events {
    worker_connections 1024;
}

http {
    server_tokens off;
    log_format docker '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /dev/stdout docker;

    include /etc/nginx/mime.types;

    server {
        listen 3000;
        server_name _;

        charset utf-8;
        client_max_body_size 5M;

        location /static {
            alias /www/application/app/static/;
        }

        location / {
            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```
We can note somethings down:
1. The user that runs the server is `www-data` (this is a precautionary method since if remote code execution is available, I avoid some issues)
2. The HTTP server has a logging format that logs the information on the `/stdout` but I tailored it to have a proper log file:
```
[program:nginx]
command=nginx -g 'daemon off;'
autostart=true
autorestart=true
stdout_logfile=/var/log/nginx/access.log
stdout_logfile_maxbytes=0
stderr_logfile=/var/log/nginx/error.log
stderr_logfile_maxbytes=0
```
3. The server listens on port `3000` and forwards the request to port `8000` where our application is listening. Hence nginx acts as a proxy between the user and the internal working application.
4. The server seems to have a proper configuration but there is an alias for the `/static` path defined:
```
location /static {
    alias /www/application/app/static/;
}
```
This does appear to be secure at surface value but it is not!

So let us proceed to look at the vulnerabilities:

### Path Traversal
To first understand this, we need to look at the **location directive**:
```
The syntax for the location directive is as follows:

location [modifier] /path/to/URL {    # other directives}

The modifier is optional and can be one of the following:

    =: Exact match
    ~: Case-sensitive regular expression match
    ~*: Case-insensitive regular expression match
    ^~: Prefix match (stop searching if this matches)
```
From the above it seems to match the directive we provided:
```
location /static { alias /www/application/app/static/; }
```
The path has been specified and another directive is in play but how does this impact the vulnerability.

Let us observe the following requests:
```bash
╰─[:)] % curl 'http://127.0.0.1/static/css/styles.css' --path-as-is -I
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 10 Mar 2025 06:34:57 GMT
Content-Type: text/css
Content-Length: 7628
Last-Modified: Sun, 09 Mar 2025 18:11:44 GMT
Connection: keep-alive
ETag: "67cdd9e0-1dcc"
Accept-Ranges: bytes


╰─[:)] % curl 'http://127.0.0.1/staticcss/styles.css' --path-as-is -I 
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 10 Mar 2025 06:35:14 GMT
Content-Type: text/css
Content-Length: 7628
Last-Modified: Sun, 09 Mar 2025 18:11:44 GMT
Connection: keep-alive
ETag: "67cdd9e0-1dcc"
Accept-Ranges: bytes
```

- Both return 200, isnt that odd ? Let us follow the steps the server took:

1. When I send a request `/static/css/styles.css` it follows the location directive according to the **Nginx configuration file**:
2. It then appends the remaining part to the path specified:
```
url = http://127.0.0.1/static/css/styles.css
location = /static
path = /css/styles.css
full path = /www/application/app/static/ + path
full path = /www/application/app/static//css/styles.css
```
- According to Unix based paths, this is a valid file path and we can confirm this in the container:
```bash
root@6868efa15290:/www/application# cat /www/application/app/static//css/styles.css | wc -c
7628
```

The 2nd request behaves the same:
```
url = http://127.0.0.1/static/css/styles.css
location = /static
path = css/styles.css
full path = /www/application/app/static/ + path
full path = /www/application/app/static/css/styles.css
```
- This is a proper valid file path and that is why the request still goes through.

Now that cannot be much, but what happens when we introduce traversal characters:
```bash
╰─[:)] % curl 'http://127.0.0.1/static..' --path-as-is -I
HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Mon, 10 Mar 2025 06:43:03 GMT
Content-Type: text/html
Content-Length: 162
Location: http://127.0.0.1:3000/static../
Connection: keep-alive
```

We are met with a **301**, which is a status code that comes up when Nginx encounters a directory, since its not a proper file it just details an error indicating it was mode permanently.

Let us step through the request again:
```
url = http://127.0.0.1/static..
location = /static
path = ..
full path = /www/application/app/static/ + path
full path = /www/application/app/static/.. = /www/application/app/
```
- This shows it tried to access the `app` directory as a file, but that is not the case hence it raised the 301 error.

Now by default, this allows us to access directories and files within those directories:
```bash
╰─[:)] % curl 'http://127.0.0.1/static../blueprints/shop.py' --path-as-is -I
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 10 Mar 2025 06:52:24 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 4837
Last-Modified: Mon, 10 Mar 2025 04:59:55 GMT
Connection: keep-alive
ETag: "67ce71cb-12e5"
Accept-Ranges: bytes
```
- This allows us to access to a file that may be impossible at first. This is how we have arbitrary read within an internal environment. Nginx assumes the first path traversal piece is part of the required path, but if we introduce more path traversal characters it filters them out and ignores it. 

Hence we need to focus on any potential files, we could bruteforce the files:
```bash
╰─[:)] % grep -ar '^secrets$' /usr/share/seclists/Discovery/Web-Content 
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt:secrets
/usr/share/seclists/Discovery/Web-Content/api/objects.txt:secrets
/usr/share/seclists/Discovery/Web-Content/dutch/new/11.txt:secrets
```
If we assume that we can enumerate the source code chances of there existing files with `*.py` appended exists widely!

```bash
╰─[:)] % curl 'http://127.0.0.1/static../secrets.py' --path-as-is -I
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 18 Mar 2025 05:27:57 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 75
Last-Modified: Tue, 18 Mar 2025 05:15:31 GMT
Connection: keep-alive
ETag: "67d90173-4b"
Accept-Ranges: bytes
``` 
- Meaning that if we have sensitive stuff, like above we can compromise a system.
In this case, it was simple. But in some cases, we have upload functionality with a tarslip chained together to achieve full arbitrary read. 

Assuming that uploads directory and static directory are in the same directory and we have a tarslip
```
uploads/f.txt -> /etc/passwd
```
Then we can be able to read such as a file! There are multiple applications with this misconfiguration, especially on the [Github search](https://github.com/search?q=%2Flocation%20%5C%2F%5B_.a-zA-Z0-9-%5C%2F%5D*%5B%5E%5C%2F%5D%5B%5Cs%5D%5C%7B%5B%5Cs%5Cn%5D*alias%20%5C%2F%5B_.a-zA-Z0-9-%5C%2F%5D*%5C%2F%3B%2F&type=code):
```txt
/location \/[_.a-zA-Z0-9-\/]*[^\/][\s]\{[\s\n]*alias \/[_.a-zA-Z0-9-\/]*\/;/
```
- That returns `6.1k` files!

In our case, we can easily enumerate the source code and find internal workings of the application to further exploit it!

Let us work on the solution!

# Solution
The fix is simple:
```
location /static/ { alias /www/application/app/static/; }
```
This forces Nginx to treat any other traversal characters as traversal characters and not part of the path. This makes it ignore such characters and removes the path traversal!

### Connecting to the server

This will be done over 3 ports specified in the report. This is since I have SMB, HTTP and the checking service running. All ways of connection have been clearly described in the report handed to the user.

### Getting the flag
After all vulnerabilities are fixed, then getting the flag should be quite simple:

```bash
# Change your IP and PORT number
╰─[:)] % curl --http0.9  http://127.0.0.1:1337
[+] Static analysis passed!
[*] Starting dynamic analysis...
[*] Stage 1: Testing endpoints
[+] Stage 1 passed!
[*] Stage 2: Testing login and registration
[+] Stage 2 passed!
[*] Stage 3: Checking vulnerabilities ...
[+] Stage 3 passed!
[+] Flag: HTB{...}
```