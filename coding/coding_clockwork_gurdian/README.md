![img](https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/banner.png)

<img src="https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />  <font size='20'>The Clockwork Guardian</font>

18<sup>th</sup> March 2025

**Prepared By:** xclow3n  
**Challenge Author(s):** makelaris  
**Difficulty:** Easy  
**Classification:** Official

## Synopsis

Write a program to compute the shortest safe path in a grid-based labyrinth Eldoria's Skywatch Spire from the starting position `(0, 0)` to the exit cell (denoted by `'E'`). The grid is composed of:

- **Safe cells:** represented by `0`
- **Hostile sentinels (obstacles):** represented by `1`
- **Exit cell:** represented by `'E'`

Movement is restricted to the four cardinal directions (up, down, left, right). If no safe path exists, the program should output `-1`.

For example, given the grid:

```py
[
    [0, 0, 1, 0, 0, 1],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 1, 1, 0, 'E']
]
```

the expected output is `8` (the minimum number of steps required to reach the exit).

## Detailed Description

You will be provided with a single input representing the grid. The labyrinth grid has the following properties:
- Each cell is either a safe path (`0`), an obstacle (`1`), or the exit (`'E'`).
- The starting position is always at `(0, 0)`, which is assumed to be safe.

Your task is to calculate the shortest safe path from the start to the exit using only valid moves (up, down, left, right). If no such path exists, output `-1`.

## Skills Required

- Basic programming in Python.
- Understanding Breadth-First Search (BFS) algorithm.
- Familiarity with grid traversal and obstacle handling.


## Skills Learned

- Implementing a BFS algorithm for shortest-path finding.
- Efficient grid traversal while handling obstacles and boundaries.
- Dealing with unsolvable grid configurations by returning an appropriate result.


## BFS Overview

Breadth-First Search (BFS) is particularly suited for finding the shortest path in an unweighted grid because it explores all cells at the current depth before moving on to the next level. This ensures that when the exit is encountered, the path taken is the shortest one.

### Key Steps

1. **Grid Initialization and Validation:**
   - The grid is represented as a 2D list.
   - Confirm that the grid is non-empty and the starting cell `(0, 0)` is safe.

2. **BFS Setup:**
   - **Queue Initialization:**  
     Use a `deque` initialized with the starting cell `(0, 0)` and an initial step count of `0`.
   - **Visited Set:**  
     Maintain a set of visited cells to prevent reprocessing.

3. **BFS Traversal:**
   - Dequeue a cell and check if it is the exit.
   - For each valid neighbor (up, down, left, right), if the cell is safe (`0`) or is the exit (`'E'`), mark it as visited and add it to the queue with an incremented step count.

4. **Handling Unreachable Exit:**
   - If all possible paths are exhausted without finding the exit, return `-1`.


## Code Implementation

Below is the Python code with improved, meaningful variable names and detailed inline comments:

```py
from collections import deque

def find_shortest_path(labyrinth):
    # Validate the labyrinth grid and starting cell.
    if not labyrinth or labyrinth[0][0] == 1:
        return -1

    num_rows = len(labyrinth)
    num_cols = len(labyrinth[0])
    
    # Initialize the BFS queue: each element is (row, col, steps_taken)
    bfs_queue = deque([(0, 0, 0)])
    visited_cells = {(0, 0)}
    
    # Define movement directions: right, down, left, up.
    movement_directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]
    
    while bfs_queue:
        current_row, current_col, steps_taken = bfs_queue.popleft()
        
        # Check if the exit is reached.
        if labyrinth[current_row][current_col] == 'E':
            return steps_taken
        
        # Explore neighboring cells.
        for delta_row, delta_col in movement_directions:
            neighbor_row = current_row + delta_row
            neighbor_col = current_col + delta_col
            
            # Ensure the neighbor is within bounds and not yet visited.
            if (0 <= neighbor_row < num_rows and 
                0 <= neighbor_col < num_cols and 
                (neighbor_row, neighbor_col) not in visited_cells):
                
                # Only consider safe cells or the exit.
                if labyrinth[neighbor_row][neighbor_col] == 0 or labyrinth[neighbor_row][neighbor_col] == 'E':
                    visited_cells.add((neighbor_row, neighbor_col))
                    bfs_queue.append((neighbor_row, neighbor_col, steps_taken + 1))
    
    # Return -1 if no safe path to the exit exists.
    return -1

input_grid = input()

print(find_shortest_path(eval(input_grid)))
```

## Additional Considerations

### Random Grid Generation

In a complete challenge solution, you might include a grid generator. A function like `gen_question()` would:
- Randomly determine grid dimensions (e.g., rows between 4 and 7, columns between 5 and 8).
- Start with all cells as safe (`0`).
- Randomly place obstacles (`1`) with a certain probability (e.g., 30%), ensuring that the start `(0, 0)` and exit `(rows-1, cols-1)` remain unblocked (with the exit explicitly set to `'E'`).
