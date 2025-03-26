import numpy as np

matrix = np.array([[88, -17, 19, -57], [45, -9, 10, -29], [-56, 11, -12, 36], [-40, 8, -9, 26]])

ans = np.linalg.inv(matrix)

flag = ''
for i in range(4):
    for j in range(4):
        flag += chr(round(ans[i][j]) + i * j + 0x41)
    flag += '-'
flag = flag[:-1]
print(flag)