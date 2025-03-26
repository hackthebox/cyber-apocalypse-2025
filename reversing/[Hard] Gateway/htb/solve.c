#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

static uint64_t xstate1;
static uint64_t xstate2;
static uint8_t rounds;

void seed() {
    xstate1 = 0xcafebabedeadbeefULL;
    xstate2 = 0xfeedfacecafebabeULL;
    rounds = 1;
}

uint64_t xorshift128p() {
    uint64_t answer = 0;
    uint64_t t = 0;
    
    for (int i = 0; i <= rounds; i++) {
        t = xstate1;
        uint64_t s = xstate2;
        xstate1 = s;
        
        t ^= (t << 23);
        t ^= (t >> 17);
        t ^= s ^ (s >> 26);
        
        xstate2 = t;
        answer = t + s;
    }
    
    rounds = t & 0xFF;
    return answer;
}

uint8_t char_bit_twiddle(uint8_t c) {
    uint64_t temp = 0;
    temp = ((uint64_t)c & 0b01010101) << 1;
    temp |= ((uint64_t)c & 0b10101010) >> 1;
    return (uint8_t)temp;
}

uint64_t crc64(uint8_t *s, size_t n) {
    uint64_t crc=0xFFFFFFFFFFFFFFFFULL;
    
    for(size_t i=0;i<n;i++) {
        crc ^= s[i];
        for(size_t j=0;j<8;j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xC96C5795D7870F42;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

int *gen_shuffle(char *inp, size_t len) {
    int *idx = malloc(sizeof(int)*len);
    for (int i = 0; i < len; i++) {
        idx[i] = i;	
    }
    for (size_t i = 0; i < len; i++) {
        uint64_t replace = xorshift128p() % len;
        int temp = idx[replace];
        idx[replace] = idx[i];
        idx[i] = temp; 
    }
    return idx;
}

void main() {
    uint32_t ans[0x20] = {0xb62a1500, 0x1d5c0861, 0x4c6f6e28, 0x4312c5af, 0x3cd56ab6, 0x1e6ab55b, 0x3cd56ab6, 0xc06c89bf, 0xed3f1f80, 0xbaf0e1e8, 0xbfab26a6, 0x3cd56ab6, 0xb3e0301b, 0xbaf0e1e8, 0xe1e5eb68, 0xb0476f74, 0xb3e0301b, 0x3cd56ab6, 0xbfab26a6, 0xe864d8ce, 0x4c6f6e28, 0x4312c5af, 0xb3e0301b, 0x9d14f94b, 0xee9840ef, 0x3cd56ab6, 0xbfab26a6, 0xbfab26a6, 0x9d14f94b, 0xbaf0e1e8, 0x14dd3bc7, 0x97329582};
    uint8_t inp[0x21] = {0};
    seed();
    int *shuffle_idx = gen_shuffle(inp, 0x20);
    for (int i = 0; i < 0x20; i++) {
        uint8_t b = 0;
        for (uint16_t c = 0; c <= 255; c++) {
            b = (uint8_t)c;
            uint32_t val = crc64(&b, 1);
            if (val == ans[i])
                break;
        }
        inp[shuffle_idx[i]] = char_bit_twiddle(b);
    }
    free(shuffle_idx);
    for (int i = 0; i < 0x20; i++) {
        printf("%c", inp[i]);
    }

    puts("");
}
