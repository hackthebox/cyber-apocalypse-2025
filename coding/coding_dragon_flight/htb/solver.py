import sys

# Helper function to create a segment tree node from a value.
def make_node(val):
    # Each node stores:
    # total sum, maximum prefix sum, maximum suffix sum, maximum subarray sum
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
    # Example:
    # 5 3
    # 10 -2 3 -1 5
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
