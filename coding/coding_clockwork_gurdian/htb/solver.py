import ast
from collections import deque

def find_shortest_path(grid):
    rows = len(grid)
    cols = len(grid[0])
    queue = deque([(0, 0, 0)])
    visited = {(0, 0)}
    directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]
    while queue:
        r, c, d = queue.popleft()
        if grid[r][c] == 'E':
            return d
        for dr, dc in directions:
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and (nr, nc) not in visited:
                if grid[nr][nc] == 0 or grid[nr][nc] == 'E':
                    visited.add((nr, nc))
                    queue.append((nr, nc, d + 1))
    return -1

grid_input = input().strip()
grid = ast.literal_eval(grid_input)
print(find_shortest_path(grid))
