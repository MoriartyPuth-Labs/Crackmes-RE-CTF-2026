# wallpaper — 15-puzzle solver (A* with Manhattan distance heuristic)
#
# The binary encodes a 15-puzzle on 16 hex nibbles (0-F).
# '0' is the blank tile.
#
# Initial state : b6fd071e9c8a3425
# Goal state    : fedcba9876543210
#
# Move encoding (direction the blank tile slides):
#   '0' = down   (+1 row)
#   '1' = right  (+1 col)
#   '2' = up     (-1 row)
#   '3' = left   (-1 col)
#
# The binary accepts a solution string wrapped as:  CMO{<moves>}
#
# Usage: python solve.py

import heapq

INITIAL = "b6fd071e9c8a3425"
GOAL    = "fedcba9876543210"

# Moves: (row_delta, col_delta, move_char)
MOVES = [
    ( 1,  0, '0'),  # blank moves down
    ( 0,  1, '1'),  # blank moves right
    (-1,  0, '2'),  # blank moves up
    ( 0, -1, '3'),  # blank moves left
]

def parse(s):
    return tuple(int(c, 16) for c in s)

def manhattan(state, goal_pos):
    dist = 0
    for i, v in enumerate(state):
        if v == 0:
            continue
        gr, gc = goal_pos[v]
        cr, cc = i >> 2, i & 3
        dist += abs(cr - gr) + abs(cc - gc)
    return dist

def solve(initial_str, goal_str):
    initial  = parse(initial_str)
    goal     = parse(goal_str)
    goal_pos = {v: (i >> 2, i & 3) for i, v in enumerate(goal)}

    h0 = manhattan(initial, goal_pos)
    # heap entries: (f_score, g_score, state, path_string)
    heap = [(h0, 0, initial, "")]
    best = {initial: 0}

    while heap:
        f, g, state, path = heapq.heappop(heap)

        if state == goal:
            return path

        if g > best.get(state, float('inf')):
            continue

        blank = state.index(0)
        br, bc = blank >> 2, blank & 3

        for dr, dc, mc in MOVES:
            nr, nc = br + dr, bc + dc
            if 0 <= nr < 4 and 0 <= nc < 4:
                ni = nr * 4 + nc
                lst = list(state)
                lst[blank], lst[ni] = lst[ni], lst[blank]
                ns = tuple(lst)
                ng = g + 1
                if ng < best.get(ns, float('inf')):
                    best[ns] = ng
                    heapq.heappush(heap, (ng + manhattan(ns, goal_pos), ng, ns, path + mc))

    return None

def verify(initial_str, moves, goal_str):
    state = list(parse(initial_str))
    for mc in moves:
        blank = state.index(0)
        br, bc = blank >> 2, blank & 3
        dr, dc = [( 1,0),(0, 1),(-1,0),(0,-1)][int(mc)]
        nr, nc = br + dr, bc + dc
        assert 0 <= nr < 4 and 0 <= nc < 4, f"invalid move '{mc}' at step {moves.index(mc)}"
        ni = nr * 4 + nc
        state[blank], state[ni] = state[ni], state[blank]
    return tuple(state) == parse(goal_str)

if __name__ == "__main__":
    print(f"Initial : {INITIAL}")
    print(f"Goal    : {GOAL}")
    print("Solving...")

    solution = solve(INITIAL, GOAL)

    if solution is None:
        print("No solution found.")
    else:
        ok = verify(INITIAL, solution, GOAL)
        print(f"Moves   : {solution}  ({len(solution)} steps, verified={ok})")
        print(f"Flag    : CMO{{{solution}}}")
