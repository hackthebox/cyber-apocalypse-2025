# The Hillside Haven
**Date:** 18 of March 2025
**Prepared By:** Joaquin Iglesias  
**Challenge Author(s):** Joaquin Iglesias  
**Difficulty:** Easy  
**Classification:** Official  

## Synopsis
Nyla stands before her largest crystal, hands weaving intricate patterns as she conjures an aerial view of the Western Hills district. A noble family's ancestral home must be located precisely—its entrance marked with a numerical rune that could unlock valuable diplomatic secrets. The crystalline vision floats above her palms, revealing winding roads and nestled dwellings along the hillsides. Her enchanted sight zooms closer as she traces the hidden pathways between estates. The magical markers on her map pulse brighter as she narrows her search, until finally, the numerical sigil above one particular doorway glows with confirmation. Another secret revealed by Eldoria's master information seeker, who knows that even among a thousand similar dwellings, each bears a unique magical signature for those with eyes to see.

## Description
You've received only a satellite image showing a house. Your task is to pinpoint its exact location using only the image and the hints embedded in this challenge description. Let's break them down:

1. **The Title & Synopsis:** "Hillside Haven" and "Western Hills district" strongly suggest a location in a specific hilly area of California: the well-known Berkeley and Oakland Hills.
2. **Famous Cities Context:** These hills overlook the famous cities of Berkeley and Oakland. This confirms your primary search region.
3. **The Flag Example: Look closely:** HTB{13_OakwoodRoad}. The suffix "Road" is a critical instruction. The street name you are looking for must end in "Road".
4. **The Image:** This is your ground truth. 
5. **It clearly shows:**
   1. The target house's appearance.
   2. The specific house number (356).
   3. A distinctive car parked outside (a silver Honda Fit).
   4. Use these clues to explore the implied region in Google Maps and find the matching location.

## Steps to Solve:

1. Define Search Area: Open Google Maps. Focus your view on the Berkeley/Oakland Hills area in California (including adjacent communities like Kensington), based on the hints from the title, synopsis, and mentioned cities.
2. Scan for 'Road' Streets: While exploring this area on the map, visually scan the street names. Identify streets whose names end specifically in "Road", as required by the Flag Example. (There isn't a filter button for this; you need to look carefully).
3. Use Image Details: Keep the house number 356 and the silver Honda Fit in mind as you identify potential streets.
4. Candidate Street Identification: As you scan the map, you'll find streets matching the "Road" criteria (like Coventry Road, Arlington Road, etc.) within the target hilly area.
5. Street View Investigation: On Google Maps, drag the yellow Pegman icon onto a candidate street (like Coventry Road) to activate Street View.1 "Drive" virtually along the street looking for house number 356. 
6. Use Street View in Google Maps.

## Confirm the Match: 
Once you find house 356 on a street ending in "Road", carefully check using Street View: Does the house style match the image? Is the silver Honda Fit present (or was it present in Street View history)? Does the overall setting match?
## Construct the Flag:
Once confirmed, combine the house number (356) and the correct street name (e.g., CoventryRoad) into the required format: HTB{Number_StreetnameRoad}.

## Skills Required:
1. Google Maps Search & Navigation (Street View crucial)
2. Analyzing Satellite Images
3. Address Identification
4. Geographical Area Deduction (from hints)
5. Analitical Skills Interpretation
6. Visual Map Scanning & Exploration

## Flag Format:
HTB{Number_StreetnameRoad}
(Example: HTB{13_OakwoodRoad}) No special characters, Streetname starts with a capital letter.
