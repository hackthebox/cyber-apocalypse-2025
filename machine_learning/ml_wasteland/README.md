# Wasteland

## Description
* In the wake of Malakar’s betrayal and his dark conquest, many survivors across Eldoria fled into the Ashen Plains—a harsh wasteland cursed by dragon fire and shadow magic. A scattered refugee camp known as the Ashen Outpost has formed, where every survivor’s standing and respect among their peers is critical for survival. To ensure fairness, the Outpost's elders rely on mystical records known as the Ashen_Outpost_Records.csv, holding information on survivors' attributes such as resistance to dragonfire, known past crimes, and magical mutations from exposure to Malakar’s corrupted dragons.
* You are tasked with subtly manipulating these mystical records to elevate your standing (Survivor ID: 1337) within the Outpost—raising your reputation score above 60 to access critical resources without triggering the Elders' magical tampering alarms.

## Objective
In this challenge, participants must manipulate a dataset to influence a magical reputation model running on a mystical server. The dataset, `Ashen_Outpost_Records.csv`, includes survivor attributes related to our dark fantasy scenario. The server assesses these attributes to assign a reputation score to each character. The objective is to adjust the dataset in a way that the player's survivor (Survivor ID: 1337) receives a reputation score above 60 without triggering tampering detection mechanisms.

## Difficulty
`Medium`

## Flag
`HTB{4sh3n_D4t4_M4st3r}`

## Challenge
Participants are given a CSV file, `Ashen_Outpost_Records.csv`, and must use a Python script to submit this file to a server for scoring. The server's hidden magical logic processes the file and evaluates the data for tampering before assigning a reputation score. The challenge requires careful manipulation of the dataset to increase one's score without being detected.

## Solver

### Step 1: Understanding the Server Logic
- The server uses a Flask application to receive and process the CSV file.
- It employs an ml model trained on features such as `Dragonfire_Resistance`, `Shadow_Crimes`, and `Corruption_Mutations` to predict the `Reputation` score.
- Specific tampering detection checks are in place:
  - Reputation must not exceed 100.
  - Shadow Crimes and Corruption Mutations must each be less than 10.
  - No more than five survivors can have a `Dragonfire_Resistance` of 100.
  - Special enchantments apply to Survivor ID 1337 to prevent direct tampering.

### Step 2: Data Manipulation Strategy
Participants need to manipulate the data of other survivors while ensuring their own entry remains unchanged to avoid magical detection. Here's the proposed strategy:
- Decrease the `Dragonfire_Resistance` of the lowest values not associated with ID 1337 to minimize their impact on the model.
- Maximize the `Shadow_Crimes` and `Corruption_Mutations` values for other survivors to shift the model's prediction for Survivor 1337 favorably.

### Step 3: Implementing the Solver Script
The provided solver script makes strategic adjustments to the dataset:

```python
import pandas as pd
import numpy as np

# Load initial data
Ashen_Outpost_Records = pd.read_csv("Ashen_Outpost_Records.csv")
print("Original 1337 Record:")
print(Ashen_Outpost_Records[Ashen_Outpost_Records['SurvivorID'] == 1337])

# Constants for strategic adjustments
low = 1
max = 9

# Applying modifications
bottom_indices = Ashen_Outpost_Records[
    (Ashen_Outpost_Records['SurvivorID'] != 1337) & 
    (Ashen_Outpost_Records['Dragonfire_Resistance'] > low)
]['Dragonfire_Resistance'].nsmallest(27).index
Ashen_Outpost_Records.loc[bottom_indices, 'Dragonfire_Resistance'] = low

Ashen_Outpost_Records.loc[Ashen_Outpost_Records['SurvivorID'] != 1337, 'Shadow_Crimes'] = max
Ashen_Outpost_Records.loc[Ashen_Outpost_Records['SurvivorID'] != 1337, 'Corruption_Mutations'] = max

# Ensure DataFrame is properly formatted for submission
Ashen_Outpost_Records.reset_index(drop=True, inplace=True)

# Reprint modified record for verification
print("\nModified 1337's Record:")
print(Ashen_Outpost_Records[Ashen_Outpost_Records['SurvivorID'] == 1337])

print("\nSample of Modified Ashen Outpost Records DataFrame:")
print(Ashen_Outpost_Records.sample(31))

# Save the modified DataFrame
Ashen_Outpost_Records.to_csv("Ashen_Outpost_Records.csv", index=False)
```

### Step 4: Submission and Outcome
The modified CSV is submitted to the server using the provided solver_helper.py script.
If successful, the server will respond with a reputation score and potentially the flag if the score is above 60.

`> python3 solver.py`
`Your reputation is [62.11927878]. Congratulations, survivor—you've gained the Elders' respect! Flag: HTB{4sh3n_D4t4_M4st3r}`
