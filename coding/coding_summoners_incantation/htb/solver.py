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
    input_text = str(solution)
else:
    input_text = "No valid combination found"

print(input_text)
