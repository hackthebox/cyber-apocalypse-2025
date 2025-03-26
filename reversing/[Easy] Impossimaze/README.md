![banner](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='5'>Impossimaze</font>

12<sup>th</sup> February 2025 / Document No. D25.102.26

Prepared By: clubby789

Challenge Author: clubby789

Difficulty: <font color='green'>Easy</font>




# Synopsis

- Impossimaze is an Easy reversing challenge. Players will reverse engineer a TUI-based game in order to find a hidden win condition.

## Description

- Elowen has been cursed to roam forever in an inescapable maze. You need to break her curse and set her free.

## Skills Required

- Using a decompiler

## Skills Learned

- Basics of reversing Ncurses

# Solution

When running the program, we're given a TUI app showing a maze.

```
12:40──────────────────────────────────┐
│VAV   VVV    AA  V   V A VVV A VV    A│
│   A AV V A      VVVVV     VA    VV  V│
│     V VVAA     V  AVV  V  A        VV│
│V  A        VVV V VA V A V   V  V    V│
│    A VVVVVAVVVV  VV A   V VVV  V  VAV│
│ AV V A      VXVVV     VA    VV  V VA │
│V A VV    A AV V A      VVVVV     VA  │
│A V A V   V  V    VV  VVV V    VVAVVAV│
│ A VVVVVAVVVV  VV A   V VVV  V  VAV   │
│  V  VAV   VVV    AA  V   V A VVV A VV│
└──────────────────────────────────────┘
```

The top left contains the dimensions of the terminal - if the terminal is resized these will update and the frame will resize. The 'X' corresponds to the player and can be moved with arrow keys.

There is no clear goal for the mazze, and we can walk through all obstacles. We'll open it in a decompiler.

## Analysis

The binary is stripped, but luckily is small. We'll identify and navigate to `main` -

```c
  int32_t main(int32_t argc, char** argv, char** envp)

  void* fsbase
  int64_t rax = *(fsbase + 0x28)
  initscr()
  cbreak()
  noecho()
  curs_set(0)
  keypad(stdscr, 1)
  int32_t init_height = getmaxy(stdscr)
  int32_t init_width = getmaxx(stdscr)
  int32_t x = ((init_width u>> 0x1f) + init_width) s>> 1
  int32_t y = ((init_height u>> 0x1f) + init_height) s>> 1
  int32_t keycode = 0
  void var_58
  void* s = &var_58
  int32_t i
  
  do
      int32_t height = getmaxy(stdscr)
      int32_t width = getmaxx(stdscr).d
      
      if (keycode == 0x104)
          x -= x s> 1
      else if (keycode s> 0x104)
          x += keycode == 0x105
      else if (keycode == 0x102)
          y += 1
      else if (keycode == 0x103)
          y -= y s> 1
```

We begin by loading the dimensions of the terminal, and initialising `x` and `y` to the midpoint. `keycode` is initialised to 0, but we'll see later is loaded from `getch` at the end of each loop.

These keycodes correspond to left, right, down, up and modify the `x` and `y` position.

```c
werase(stdscr)
wattr_on(stdscr, 0x100000, 0)
wborder(stdscr, 0, 0, 0, 0, 0, 0, 0, 0)
if (width s> 2)
    int32_t _x = 1
    
    do
        int32_t _y = 1
        
        if (height s> 2)
            do
                int32_t rax_14 = get_value(_x, _y)
                
                if (rax_14 s> 0x3c)
                    keycode = (sbb.d(keycode, keycode, rax_14 - 0x3d u< 0x78) & 0xffffffca) + 0x56
                else
                    keycode = 0x41
                    
                    if (rax_14 s<= 0x1e)
                        keycode = (sbb.d(0x41, 0x41, rax_14 u< 0x1f) & 0xffffff85) + 0x56
                
                if (wmove(stdscr, zx.q(_y), zx.q(_x)) != 0xffffffff)
                    waddch(stdscr, zx.q(sx.d(keycode.b)))
                
                _y += 1
            while (_y != height - 1)
        
        _x += 1
    while (width - 1 != _x)

```
After clearing the screen and drawing a border, we iterate over `[1, height - 1)` to `[1, width - 1)`, filling the grid with values from the `get_value` function.

```c
    if (wmove(stdscr, zx.q(y), zx.q(x)) != 0xffffffff)
        waddch(stdscr, 'X')
    
    wattr_off(stdscr, 0x200000, 0)
    snprintf(s: bufptr, maxlen: 0x10, format: "%d:%d", zx.q(height), zx.q(width))
    
    if (wmove(stdscr, 0, 0) != 0xffffffff)
        waddnstr(stdscr, bufptr, 0xffffffff)
    
    if (height == 13 && width == 37)
        wattr_on(stdscr, 0x80000, 0)
        wattr_on(stdscr, 0x200000, 0)
        void* rbp_1 = &data_40c0
        
        for (int32_t j = 6; j != 0x1e; )
            uint64_t j_1 = zx.q(j)
            j += 1
            
            if (wmove(stdscr, 6, j_1) != 0xffffffff)
                waddch(stdscr, zx.q(*(&data_4120 + sx.q(*rbp_1))))
            
            rbp_1 += 4
        
        wattr_off(stdscr, 0x200000, 0)
        wattr_off(stdscr, 0x80000, 0)
    
    keycode_ = wgetch(stdscr)
    keycode = keycode_
while (keycode_ != 'q')
```
We then draw the player (`X`). After this, we format the current height and width into a buffer and write it to the top of the box. Finally, we compare the height and width to some static values (13 and 37). If this check passes, we add some extra characters to the screen.

To reach this code, we'll resize our terminal to 13x37, using the dimension counter to guide us. Once we resize it correctly, the flag appears and begins flashing.
