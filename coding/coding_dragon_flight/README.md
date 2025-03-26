![img](https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/banner.png)

<img src="https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />  <font size='20'>Dragon Flight</font>

18<sup>th</sup> March 2025

**Prepared By:** xclow3n  
**Challenge Author(s):** xclow3n
**Difficulty:** Easy  
**Classification:** Official


## Challenge Story and Objective

In the mystical realm of the Floating Isles, ancient dragons traverse the skies between floating sanctuaries. However, unpredictable winds now pose a dynamic threat to their journey! As a Dragon Flight Master, you are entrusted with the critical mission to:

- **Adapt to Changing Winds:** Process update operations that modify the wind effect on any flight segment.
- **Chart the Best Route:** Answer queries that compute the maximum favorable continuous flight stretch—the maximum contiguous subarray sum—over any specified segment range.

Your task is to ensure the dragons always have the safest and most efficient route by dynamically adjusting to shifting wind conditions.

---

## Problem Description

### What Is the Input?

The input provided to the challenge is structured as follows:

1. **First Line:**  
   Two space-separated integers, **N** and **Q**.
   - **N:** Represents the number of flight segments.
   - **Q:** Represents the number of operations to perform.

2. **Second Line:**  
   **N** space-separated integers representing the initial net wind effects for each flight segment.
   - A **positive** value indicates a tailwind (boosting the dragon’s flight distance).
   - A **negative** value indicates a headwind (reducing the effective flight distance).

3. **Next Q Lines:**  
   Each line represents an operation that can be one of the following:
   - **`U i x` (Update Operation):**  
     Update the wind effect on the *i*-th flight segment to **x**.
   - **`Q l r` (Query Operation):**  
     Query the maximum contiguous subarray sum (i.e., the maximum net flight distance) for the segments in the range from **l** to **r** (inclusive).

### What Are We Supposed to Do?

You must design and implement a program that can:
- **Process dynamic updates:** When a wind effect changes on a segment, update the internal data structure.
- **Answer range queries:** For any given query, compute the maximum contiguous subarray sum for the specified segment range.

Due to the frequent updates and queries, your solution must be efficient, with both operations ideally running in logarithmic time.

---

## Sample Input and Expected Output

### Flight Path Input

```
6 6
-10 -7 -1 -4 0 -5
Q 3 3
U 2 9
Q 6 6
U 1 -1
Q 6 6
U 5 -9
```

### Expected Output

```
-1
-5
-5
```

### Step-by-Step Explanation

1. **Initial Array:**  
   `[-10, -7, -1, -4, 0, -5]`  
   - Negative values indicate headwinds, which reduce flight distance.

2. **Operation 1: `Q 3 3`**  
   - **Query:** The subarray from index 3 (1-indexed) is `[-1]`.  
   - **Result:** Maximum subarray sum is `-1`.

3. **Operation 2: `U 2 9`**  
   - **Update:** Change the value at the 2nd segment from `-7` to `9`.  
   - **New Array:** `[-10, 9, -1, -4, 0, -5]`.

4. **Operation 3: `Q 6 6`**  
   - **Query:** The subarray from index 6 is `[-5]`.  
   - **Result:** Maximum subarray sum is `-5`.

5. **Operation 4: `U 1 -1`**  
   - **Update:** Change the value at the 1st segment from `-10` to `-1`.  
   - **New Array:** `[-1, 9, -1, -4, 0, -5]`.

6. **Operation 5: `Q 6 6`**  
   - **Query:** The subarray from index 6 remains `[-5]`.  
   - **Result:** Maximum subarray sum is `-5`.

7. **Operation 6: `U 5 -9`**  
   - **Update:** Change the value at the 5th segment from `0` to `-9`.  
   - **Final Array:** `[-1, 9, -1, -4, -9, -5]`.

---

## The Segment Tree Solution

### Why Use a Segment Tree?

The challenge involves a mix of point updates (changing wind effects on individual segments) and range queries (finding the maximum contiguous subarray sum over a segment range). A segment tree is ideal because it provides:
- **Efficient Updates:** Modify a single element and update the tree in O(log N) time.
- **Efficient Queries:** Retrieve aggregated information for any range in O(log N) time.

### What Does Each Node Store?

Each node in the segment tree stores four key values for the corresponding segment:
- **Total Sum:** The sum of all elements in the segment.
- **Maximum Prefix Sum:** The best sum obtainable starting from the leftmost element.
- **Maximum Suffix Sum:** The best sum obtainable ending at the rightmost element.
- **Maximum Subarray Sum:** The maximum contiguous subarray sum anywhere in the segment.

### Building and Merging Nodes

1. **Creating a Node:**

   For a single element `val`, create a node as follows:
   ```python
   def make_node(val):
       return (val, val, val, val)
   ```

2. **Merging Two Nodes:**

   When merging two nodes (`left` and `right`), compute:
   ```python
   def merge(left, right):
       total = left[0] + right[0]
       prefix = max(left[1], left[0] + right[1])
       suffix = max(right[2], right[0] + left[2])
       max_sub = max(left[3], right[3], left[2] + right[1])
       return (total, prefix, suffix, max_sub)
   ```
   This merge function combines information from two segments to compute the overall best contiguous subarray sum.

### Building, Updating, and Querying the Tree

- **Building the Tree:**  
  The `build_tree` function recursively constructs the tree, storing the node information for every segment of the array.
  
- **Updating the Tree:**  
  The `update_tree` function is used for update operations. It locates the leaf node corresponding to the updated index, changes its value, and then merges the updated information back up the tree.
  
- **Querying the Tree:**  
  The `query_tree` function retrieves the node representing a given range [l, r]. The maximum contiguous subarray sum for that range is then available directly from the node.

---

## Complete Solution Code

```python
import sys

# Helper function to create a segment tree node from a value.
def make_node(val):
    # Each node stores:
    # (total sum, maximum prefix sum, maximum suffix sum, maximum subarray sum)
    return (val, val, val, val)

# Merge two segment tree nodes.
def merge(left, right):
    total = left[0] + right[0]
    prefix = max(left[1], left[0] + right[1])
    suffix = max(right[2], right[0] + left[2])
    max_sub = max(left[3], right[3], left[2] + right[1])
    return (total, prefix, suffix, max_sub)

# Build the segment tree recursively.
def build_tree(arr, tree, node, start, end):
    if start == end:
        tree[node] = make_node(arr[start])
    else:
        mid = (start + end) // 2
        build_tree(arr, tree, node * 2, start, mid)
        build_tree(arr, tree, node * 2 + 1, mid + 1, end)
        tree[node] = merge(tree[node * 2], tree[node * 2 + 1])

# Update the segment tree at position pos with new value new_val.
def update_tree(tree, node, start, end, pos, new_val):
    if start == end:
        tree[node] = make_node(new_val)
    else:
        mid = (start + end) // 2
        if pos <= mid:
            update_tree(tree, node * 2, start, mid, pos, new_val)
        else:
            update_tree(tree, node * 2 + 1, mid + 1, end, pos, new_val)
        tree[node] = merge(tree[node * 2], tree[node * 2 + 1])

# Query the segment tree for the range [L, R].
def query_tree(tree, node, start, end, L, R):
    if R < start or L > end:
        return None  # Out of range.
    if L <= start and end <= R:
        return tree[node]
    mid = (start + end) // 2
    left_node = query_tree(tree, node * 2, start, mid, L, R)
    right_node = query_tree(tree, node * 2 + 1, mid + 1, end, L, R)
    if left_node is None:
        return right_node
    if right_node is None:
        return left_node
    return merge(left_node, right_node)

# Main solution function.
if __name__ == '__main__':
    # Read the first two input lines.
    # For example:
    # 6 6
    # -10 -7 -1 -4 0 -5
    input1 = input().strip()
    input2 = input().strip()
    N, Q = map(int, input1.split())
    arr = list(map(int, input2.split()))

    # Build the segment tree. We use an array "tree" of size 4*N.
    tree = [None] * (4 * N)
    build_tree(arr, tree, 1, 0, N - 1)

    # Process the next Q operations.
    for _ in range(Q):
        op_line = input().strip().split()
        op = op_line[0]
        if op == 'Q':
            # Query operation: Q l r (1-indexed)
            l = int(op_line[1]) - 1  # convert to 0-indexed
            r = int(op_line[2]) - 1
            result = query_tree(tree, 1, 0, N - 1, l, r)
            # The answer is the maximum subarray sum in the queried range.
            print(result[3] if result is not None else 0)
        elif op == 'U':
            # Update operation: U i x (1-indexed index)
            i = int(op_line[1]) - 1  # convert to 0-indexed
            x = int(op_line[2])
            update_tree(tree, 1, 0, N - 1, i, x)
```

