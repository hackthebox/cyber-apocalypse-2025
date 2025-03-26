![img](https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/banner.png)

<img src="https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />  <font size='20'>Dragon Fury</font>

18<sup>th</sup> March 2025

**Prepared By:** xclow3n  
**Challenge Author(s):** makelaris, xclow3n
**Difficulty:** Easy  
**Classification:** Official

---

## Challenge Story and Objective

In the epic battle against Malakar's dark forces, the ancient dragons must unleash a series of precise attacks. Each round of battle offers several potential damage values, but only one unique combination of these attacks will sum up exactly to the damage required to vanquish the enemy.

**Your Task:**

- **Input Processing:**  
  Read a single string that represents a list of subarrays. Each subarray contains possible damage values for one round of attack.  
  _Example:_  
  ```python
  [[13, 15, 27, 17], [24, 15, 28, 6, 15, 16], [7, 25, 10, 14, 11], [23, 30, 14, 10]]
  ```

- **Target Damage:**  
  Read an integer `T` representing the target total damage required to defeat the enemy.

- **Determine the Correct Attack Combination:**  
  Pick exactly one damage value from each subarray so that their sum equals `T`. It is guaranteed that there is exactly one valid solution.

- **Output:**  
  Output the valid combination as a list.

---

## Input Format Explanation

1. **First Input Line:**  
   A single string representing a list of subarrays.  
   - Each subarray corresponds to a round of attack and contains several possible damage values.

2. **Second Input Line:**  
   An integer `T` that represents the target total damage required.

**Example Input:**

```
[[13, 15, 27, 17], [24, 15, 28, 6, 15, 16], [7, 25, 10, 14, 11], [23, 30, 14, 10]]
77
```

---

## Example Walkthrough

### Provided Input

```
[[13, 15, 27, 17], [24, 15, 28, 6, 15, 16], [7, 25, 10, 14, 11], [23, 30, 14, 10]]
77
```

### Explanation:

1. **Subarrays (Rounds):**  
   - Round 1: `[13, 15, 27, 17]`
   - Round 2: `[24, 15, 28, 6, 15, 16]`
   - Round 3: `[7, 25, 10, 14, 11]`
   - Round 4: `[23, 30, 14, 10]`

2. **Target Damage:**  
   The target total damage is `77`.

3. **Task:**  
   Choose one damage value from each round such that the sum equals 77.

4. **Valid Combination:**  
   The only valid solution is `[13, 24, 10, 30]` since:  
   `13 + 24 + 10 + 30 = 77`

### Expected Output

```
[13, 24, 10, 30]
```

---

## Detailed Explanation of the Solution

### Approach

To solve the problem, we use the following steps:

1. **Parsing Input:**  
   - The first line is a string representing the list of subarrays. We use `ast.literal_eval` to convert it into a Python list.
   - The second line is converted to an integer representing the target damage.

2. **Generating Combinations:**  
   - We use Python's `itertools.product` to iterate over every possible combination where one element is picked from each subarray.
   
3. **Checking for the Valid Combination:**  
   - For each combination, we calculate the sum.
   - If the sum equals the target damage, we have found the unique valid solution.
   
4. **Output the Result:**  
   - The valid combination is then output as a list.

### Code Walkthrough

Below is the complete solution code:

```python
import ast
from itertools import product

# Read the first line: a string representing a list of subarrays.
input_arr = input().strip()  # For example: "[[13, 15, 27, 17], [24, 15, 28, 6, 15, 16], [7, 25, 10, 14, 11], [23, 30, 14, 10]]"
# Read the second line: the target total damage.
total_str = input().strip()  # For example: "77"

# Convert the input string to a Python list and parse the target as an integer.
arrays = ast.literal_eval(input_arr)
target = int(total_str)

# Iterate over every possible combination: one element from each subarray.
solution = None
for combo in product(*arrays):
    if sum(combo) == target:
        solution = list(combo)
        break

# Prepare the output text.
if solution is not None:
    output_text = str(solution)
else:
    output_text = "No valid combination found"

print(output_text)
```
