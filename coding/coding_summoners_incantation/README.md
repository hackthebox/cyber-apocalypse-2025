![img](https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/banner.png)

<img src="https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />  <font size='20'>Summoners Incantation</font>

18<sup>th</sup> March 2025

**Prepared By:** xclow3n  
**Challenge Author(s):** makelaris
**Difficulty:** Easy  
**Classification:** Official

---

## Challenge Story and Objective

Deep within the ancient halls lies the secret of the Dragon's Heart—a power that can only be unlocked by combining magical tokens in just the right way. The tokens are delicate: if you combine two adjacent tokens, their energy dissipates into the void.

**Your Quest:**  
Determine the maximum amount of energy that can be harnessed by selecting tokens such that no two selected tokens are adjacent. This is equivalent to finding the maximum sum of non-adjacent numbers from a list of token energies.

---

## Input and Output Format

### Input Format

- **Single Line Input:**  
  A Python-style list of integers representing the energy values of tokens.
  
  **Example:**  
  ```python
  [3, 2, 5, 10, 7]
  ```

### Output Format

- **Output:**  
  A single integer representing the maximum energy obtainable by summing non-adjacent tokens.

---

## Example Cases

### Example 1

**Input:**

```python
[3, 2, 5, 10, 7]
```

**Output:**

```python
15
```

**Explanation:**  
The optimal selection is to pick tokens with energies 3, 5, and 7 (non-adjacent). Their sum is 3 + 5 + 7 = 15.

---

### Example 2

**Input:**

```python
[10, 18, 4, 7]
```

**Output:**

```python
25
```

**Explanation:**  
The best choice is to select tokens with energies 18 and 7 (positions 2 and 4) to get a total of 18 + 7 = 25.

---

## Detailed Explanation of the Solution

The problem asks us to choose non-adjacent tokens such that their total energy is maximized. This is a classic dynamic programming problem known as the "Maximum Sum of Non-Adjacent Numbers."

### Approach

1. **Base Cases:**
   - If there are no tokens, the maximum sum is 0.
   - If there is only one token, the maximum sum is the value of that token.

2. **Dynamic Programming Setup:**
   - Use an array `dp` where `dp[i]` represents the maximum sum obtainable considering tokens up to index `i`.
   - For the first token, `dp[0] = tokens[0]`.
   - For the second token, `dp[1] = max(tokens[0], tokens[1])`.

3. **Transition:**
   - For every subsequent token at index `i` (starting from 2), decide whether to take that token or not:
     - **Exclude token `i`:** The maximum sum remains `dp[i-1]`.
     - **Include token `i`:** Add its energy to `dp[i-2]` because we cannot take the immediately previous token.
   - Thus, the recurrence relation is:
     ```python
     dp[i] = max(dp[i-1], dp[i-2] + tokens[i])
     ```

4. **Final Answer:**
   - The answer is `dp[-1]`, which holds the maximum energy obtainable.

### Code Implementation

Below is the complete code solution:

```python
def max_non_adjacent(tokens):
    """
    Returns the maximum sum of non-adjacent values in tokens.
    """
    n = len(tokens)
    if n == 0:
        return 0
    if n == 1:
        return tokens[0]
    dp = [0] * n
    dp[0] = tokens[0]
    dp[1] = max(tokens[0], tokens[1])
    for i in range(2, n):
        dp[i] = max(dp[i-1], dp[i-2] + tokens[i])
    return dp[-1]

tokens = eval(input().strip())
print(max_non_adjacent(tokens))
```
