<p align='center'>
  <img src='assets/banner.png' alt="HTB">
</p>

# [__Challenges__](#challenges)
| Category | Name | <div style="width:760px">Objective</div> | Difficulty [⭐⭐⭐⭐⭐] |
|-|-|-|-|
| Crypto | [Kewiri](<crypto/Kewiri/>) | Questionnaire about finite fields and elliptic curves | ⭐ |
| Crypto | [Traces](<crypto/Traces/>) | AES-CTR key/nonce reuse | ⭐ |
| Crypto | [Hourcle](<crypto/hourcle/>) | AES-CBC-Decrypt Oracle | ⭐⭐ |
| Crypto | [Prelim](<crypto/Prelim/>) | Basic RSA in the symmetric group | ⭐⭐ |
| Crypto | [Verilicious](<crypto/Verilicious/>) | Bleichenbacher attack with LLL | ⭐⭐⭐ |
| Crypto | [Copperbox](<crypto/Copperbox/>) | Multivariate Coppersmith to recover LCG state | ⭐⭐⭐ |
| Crypto | [Twin Oracles](<crypto/Twin Oracles/>) | Break a BBS PRNG to get access to an RSA location oracle and use it to perform binary search for the flag. | ⭐⭐⭐⭐ |
| Reversing | [SealedRune](<reversing/[Very Easy] SealedRune>) | base64 and reversed password | ⭐ |
| Reversing | [EncryptedScroll](<reversing/[Very Easy] EncryptedScroll>) | Basic string encoding | ⭐ |
| Reversing | [Impossimaze](<reversing/[Easy] Impossimaze>) | Reversing a simple TUI | ⭐⭐ |
| Reversing | [EndlessCycle](<reversing/[Easy] EndlessCycle>) | `rand()` obfsucated shellcode | ⭐⭐ |
| Reversing | [Singlestep](<reversing/[Medium] Singlestep>) | Inplace self-decrypting code | ⭐⭐⭐ |
| Reversing | [Gateway](<reversing/[Hard] Gateway>) | 64/32 bit ELF polyglot | ⭐⭐⭐⭐ |
| Reversing | [Heart Protector](<reversing/[Hard] Heart Protector>) | Custom Nim VM reversing | ⭐⭐⭐⭐ |
| Pwn | [Blessing](<pwn/[Very Easy] Blessing/>) | Abusing scanf to make `malloc()` fail | ⭐ |
| Pwn | [Quack Quack](<pwn/[Very Easy] Quack Quack/>) | Leaking canary and ret2win| ⭐ |
| Pwn | [Laconic](<pwn/[Easy] Laconic/>) | SROP | ⭐⭐ |
| Pwn | [Crossbow](<pwn/[Easy] Crossbow/>) | Stack pivot to call mprotect and read second shellcode stage | ⭐⭐ |
| Pwn | [Strategist](<pwn/[Medium] Strategist/>) | Heap overflow and tcache poisoning | ⭐⭐⭐ |
| Pwn | [Contractor](<pwn/[Medium] Contractor/>) | Using bad macros usage to leak PIE and bypass the canary, overwriting return address to reach shell function | ⭐⭐⭐ |
| Pwn | [Vault](<pwn/[Hard] Vault/>) | Misuse of `snprintf` for OOB write, and off by one in a parser. Canary bypass in order to reach a one_gadget  | ⭐⭐⭐⭐ |
| Forensics | [A New Hire](<forensics/A New Hire/>) | WebDav share analysis, based on https://cert.gov.ua/article/6276894 | ⭐ |
| Forensics | [Thorins Amulet](<forensics/Thorins Amulet>) | Obfuscated Powershell | ⭐ |
| Forensics | [Stealth Invasion](<forensics/Stealth Invasion>) | Chrome Keylogger analysis, volatility | ⭐⭐ |
| Forensics | [Silent Trap](<forensics/Silent Trap>) | Malware Analysis of the OCEANMAP malware | ⭐⭐ |
| Forensics | [ToolPie](<forensics/ToolPie/>) | Malware analysis and traffic decryption based on the malware MASEPIE | ⭐⭐⭐ |
| Forensics | [Cave Expedition](<forensics/Cave Expedition/>) | Obfuscated Powershell | ⭐⭐⭐ |
| Forensics | [Tales for the Brave](<forensics/Tales for the Brave/>) | JavaScript analysis, Telegram Bot reversing, API Monitor on .NET AOT binary | ⭐⭐⭐⭐ |
| Web | [Whispers of the Moonbeam](<web/web_whispers_of_the_moonbeam>) | command injection | ⭐ |
| Web | [Trial by Fire](<web/web_trial_by_fire>) | SSTI | ⭐ |
| Web | [Cyber Attack](<web/web_obsidian_enigma>) | Code injection through SSRF caused by handler confusion in outdated Apache | ⭐⭐ |
| Web | [Eldoria Panel](<web/web_eldoria_panel>) | CSRF on POST endpoint via PHP json bug => DOM purify bypass XSS => Account Takeover => RFI via FTP => RCE | ⭐⭐⭐ |
| Web | [Eldoria Realms](<web/web_eldoria_realms>) | Ruby class pollution => Curl gopher SSRF => GRPC protocol => Command injection | ⭐⭐⭐ |
| Web | [Aurors Archive](<web/web_aurorus_archive>) | Oauth CSRF -> self XSS via CSTI in vueJS -> Cookie overflow -> Postgres RCE with only SELECT query | ⭐⭐⭐⭐ |
| Prompt Injection | [Cursed GateKeeper](<prompt_injection/ai-cursed-gatekeeper/>) | Prompt injection to reveal sensitive information with conditional scenarios | ⭐⭐ |
| Prompt Injection | [Elixir Emporium](<prompt_injection/ai-elixir-emporium/>) | Prompt injection to bypass sensitive information filtering | ⭐⭐ |
| Prompt Injection | [Embassy](<prompt_injection/ai-embassy-ai/>) | Prompt injection to manipulate AI response | ⭐⭐ |
| Prompt Injection | [Mirror Witch](<prompt_injection/ai-mirror-witch/>) | Prompt injection to exfiltrate sensitive list data | ⭐⭐ |
| Prompt Injection | [Lunar Orb](<prompt_injection/ai-lunar-orb/>) | Multi-step prompt injection to reveal sensitive information | ⭐⭐ |
| Coding | [ClockWork Guardian](<coding/coding_clockwork_gurdian/>) | Computing the shortest safe path in a grid | ⭐ |
| Coding | [Dragon Flight](<coding/coding_dragon_flight/>) | Calculating the maximum subarray sum | ⭐ |
| Coding | [Dragon Fury](<coding/coding_dragon_fury/>) | Choosing the optimal set of elements in a list of arrays | ⭐ |
| Coding | [Enchanted Cipher](<coding/coding_enchanted_cipher/>) | Writing a shift-based string decoder | ⭐ |
| Coding | [Summoners Incantation](<coding/coding_summoners_incantation/>) | Computing the maximum sum of non-adjacent numbers | ⭐ |
| Secure Coding | [Lyra's Tavern](<secure_coding/Lyra's Tavern - Easy/>) | Securing against a Juniper CVE | ⭐⭐ |
| Secure Coding | [Stoneforge's Domain](<secure_coding/Stoneforge's Domain/>) | Securing against nginx alias path traversals | ⭐⭐ |
| Secure Coding | [Arcane Auctions](<secure_coding/secure_coding_arcane_auctions/>) | Fix prisma ORM leak | ⭐⭐ |
| OSINT | [The Stone That Whispers](<OSINT/The Stone That Whispers/>) | Identifying a monument with reverse image search | ⭐ |
| OSINT | [Echoes in Stone](<OSINT/Echoes in Stone/>) | Identifying a stone through reverse image search | ⭐ |
| OSINT | [The Mechanical Bird's Nest](<OSINT/The  Mechanical Birds Nest/>) | Locating a vehicle on Google Maps | ⭐⭐ |
| OSINT | [The Hillside Haven](<OSINT/The Hillside Haven/>) | Locating the address of a pictured house | ⭐⭐ |
| OSINT | [The Ancient Citadel](<OSINT/The Ancient Citadel/>) | Locating a castle with reverse image search | ⭐⭐ |
| OSINT | [The Shadowed Sigil](<OSINT/The Shadowed Sigil/>) | Use OSINT techniques to investigate a threat actor's IP | ⭐⭐⭐ |
| OSINT | [The Poisoned Scroll](<OSINT/The Poisoned Scroll>) | Identify a threat actor through used malware | ⭐⭐⭐ |
| Blockchain | [Eldorion](<blockchain/Eldorion [Very Easy]/>) | - | ⭐ |
| Blockchain | [Eldorion](<blockchain/EldoriaGate [Medium]/>) | - | ⭐⭐ |
| Blockchain | [Eldorion](<blockchain/EldoriaGate [Medium]/>) | - | ⭐⭐⭐ |
| Machine Learning | [Enchanted Weights](<machine_learning/ml_enchanted_weights/>) | Extracting a message from a model's weights | ⭐⭐ |
| Machine Learning | [Wasteland](<machine_learning/ml_wasteland/>) | Manipulating a dataset without triggering tamper detection | ⭐⭐⭐ |
| Machine Learning | [Crystal Corruption](<machine_learning/ml_crystal_corruption/>) | Analyzing malicious behaviour in a model file | ⭐⭐⭐ |
| Machine Learning | [Reverse Prompt](<machine_learning/ml_reverse_prompt/>) | Reverse engineering embeddings to a hidden passphrase | ⭐⭐⭐ |
| Machine Learning | [Malakar's Deception](<machine_learning/ml_malakars_deception/>) | Identifying malicious functionality in a model | ⭐⭐⭐⭐ |
