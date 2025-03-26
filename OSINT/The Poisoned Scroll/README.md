# The Poisoned Scroll

**Date:** 18 of March 2025 
**Prepared By:** Joaquin Iglesias  
**Challenge Author(s):** Joaquin Iglesias  
**Difficulty:** Medium  
**Classification:** Official  

## Synopsis
In her crystal-lit sanctum, Nyla examines reports of a series of magical attacks against the ruling council of Germinia, Eldoria's eastern ally. The attacks all bear the signature of the Shadow Ravens, a notorious cabal of dark mages known for their espionage across the realms. Her fingers trace connections between affected scrolls and contaminated artifacts, seeking the specific enchantment weapon deployed against the Germinian leaders. The runes along her sleeves pulse rhythmically as she sifts through intercepted messages and magical residue analyses from the attack sites. Her network of information crystals glows brighter as patterns emerge in the magical attacks—each victim touched by the same corrupting spell, though disguised under different manifestations. Finally, the name of the specific dark enchantment materializes in glowing script above her central crystal. Another dangerous threat identified by Eldoria's master information seeker, who knows that even the most sophisticated magical weapons leave distinctive traces for those who know how to read the patterns of corruption.

## Description
Threat intelligence reports suggest that APT29 has been using a sophisticated malware variant in their campaigns against German political parties. Your mission is to:
1. Investigate the malware used by APT29 in these attacks.
2. Confirm the malware variant based on available information.

This challenge tests your research and OSINT pivoting skills—if you dig into the right sources, you’ll uncover the malware behind the attack.

## Skills Required:
Internet Search & OSINT Pivoting  
Investigating Threat Intelligence Reports  
Malware Attribution  
Threat Intelligence Analysis  

## Skills Learned:
How to identify and attribute malware used by APT groups  
How to extract intelligence from publicly available reports  
How to correlate OSINT data to pinpoint malicious activities  

## Enumeration
### Step 1: Investigate APT29’s Recent Campaign
APT29 is known for its cyber espionage operations. A recent report mentions their attack on German political parties. Search for reports and blog posts that describe these activities.

**Key Finding:** A Google Cloud blog post from February 2024 provides insight into the malware used.

### Step 2: Identify the Malware
The blog post from Google Cloud provides key details on the malware used by APT29 in these attacks. Read through the article to find the name of the malware deployed in the German political party attack.

## Flag Extraction
Once you identify the malware variant, submit the flag in the following format:
```
HTB{malware_name}
```
