# The Shadowed Sigil

**Date:** 18 of March 2025
**Prepared By:** Joaquin Iglesias  
**Challenge Author(s):** Joaquin Iglesias  
**Difficulty:** Medium  
**Classification:** Official  

## Synopsis
In the central chamber of Eldoria's Arcane Archives, Nyla studies a glowing sigil captured by the royal wardens. The ethereal marking—"139.5.177.205"—pulsates with malicious energy, having appeared in multiple magical breaches across the realm. Her fingers trace the sigil's unique pattern as her network of crystals begins to search through records of known dark covens and their magical signatures. The runes along her sleeves flash with recognition as connections form between seemingly unrelated incidents. Each magical attack bears the same underlying pattern, the same arcane origin. Her enchanted sight follows the magical threads backward through time and space until the name of a notorious cabal of shadow mages materializes in glowing script. Another dangerous secret revealed by Eldoria's master information seeker, who knows that even the most elusive malefactors leave traces of their magic for those skilled enough to recognize their unique signature.

## Description
Threat intelligence reports suggest **139.5.177.205** has been involved in espionage campaigns. However, its attribution remains unclear. Your mission is to:
1. Investigate the IP address using **OSINT techniques**.  
2. Search for **security reports or databases** linking it to an APT.  
3. Confirm the **responsible threat actor** based on your findings.  

This challenge tests your **Google-Fu, OSINT pivoting, and attribution skills**—if you look in the right places, you’ll find the answer.

## Skills Required:
Internet Search & OSINT Pivoting  
Investigating Threat Intelligence Reports  
IOC (Indicator of Compromise) Analysis  

## Skills Learned:
How to identify malicious IPs using open sources  
How to extract intelligence from GitHub & IOC reports  
How to correlate OSINT data to known APT groups  

## Enumeration
### Step 1: Investigate the IP Address
A basic Google search can sometimes reveal hidden gems. Try searching for:
```
139.5.177.205
```

**Key Finding:** The IP appears in a GitHub repository.  

### Step 2: Digging Deeper into GitHub
One of the search results will lead to this GitHub repository:
```
APT28 IOC List
```

Once inside the repository, open the `Amber-1-IOC-IP.txt` file.  

**Key Finding:** **139.5.177.205** is listed under known **APT28** infrastructure.

## Flag Extraction
Once you confirm the APT group responsible, submit the flag in the correct format:
```
HTB{APTGROUPNUMBER}
```
