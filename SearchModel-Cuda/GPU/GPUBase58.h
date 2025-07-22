/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

// ---------------------------------------------------------------------------------
// Base58
// ---------------------------------------------------------------------------------

__device__ __constant__ char pszBase58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

__device__ __constant__ int8_t b58digits_map[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
};


// --- START OF FINAL CORRECTED FUNCTION ---
__device__ __noinline__ void _GetAddress(int type, uint32_t *hash, char *b58Add)
{
    unsigned char A[25];
    unsigned char *addPtr = A;
    int retPos = 0;
    unsigned char digits[128];

    // --- Checksum Calculation (Corrected Logic using low-level primitives) ---
    uint32_t s[8]; // SHA256 state
    uint32_t chunk[16]; // 64-byte chunk for transform

    // Step 1: First hash of (0x00 || 20-byte hash). Message is 21 bytes.
    // Manually create the first (and only) padded 64-byte block.
    unsigned char sha_input_buf[64];
    sha_input_buf[0] = 0x00;
    memcpy(sha_input_buf + 1, (unsigned char*)hash, 20);
    sha_input_buf[21] = 0x80; // Padding starts here
    for(int i = 22; i < 56; i++) {
        sha_input_buf[i] = 0x00;
    }
    // Length in bits (21 * 8 = 168) in big-endian format
    sha_input_buf[56] = 0x00; sha_input_buf[57] = 0x00; sha_input_buf[58] = 0x00; sha_input_buf[59] = 0x00;
    sha_input_buf[60] = 0x00; sha_input_buf[61] = 0x00; sha_input_buf[62] = 0x01; sha_input_buf[63] = 0x08;

    SHA256Initialize(s);
    SHA256Transform(s, (uint32_t*)sha_input_buf); // s now holds the first hash result

    // Step 2: Second hash of the 32-byte result from the first hash.
    // The state `s` is the 32-byte message. Pad it to 64 bytes.
    memcpy(sha_input_buf, (unsigned char*)s, 32);
    sha_input_buf[32] = 0x80; // Padding starts here
    for(int i = 33; i < 56; i++) {
        sha_input_buf[i] = 0x00;
    }
    // Length in bits (32 * 8 = 256) in big-endian format
    sha_input_buf[62] = 0x01; sha_input_buf[63] = 0x00; // 256 = 0x100

    SHA256Initialize(s);
    SHA256Transform(s, (uint32_t*)sha_input_buf); // s now holds the final hash result

    // Step 3: The checksum is the first 4 bytes of the final hash.
    // The SHA256 transform produces big-endian words in the state array.
    unsigned char checksum[4];
    checksum[0] = (s[0] >> 24) & 0xFF;
    checksum[1] = (s[0] >> 16) & 0xFF;
    checksum[2] = (s[0] >> 8) & 0xFF;
    checksum[3] = s[0] & 0xFF;

    // Step 4: Assemble the 25-byte address payload
    A[0] = 0x00;
    memcpy(A + 1, (unsigned char*)hash, 20);
    memcpy(A + 21, checksum, 4);

    // --- Base58 Encoding (Original, Stable Logic) ---
    // Skip leading zeroes
    while (addPtr < (A + 25) && *addPtr == 0) {
        b58Add[retPos++] = '1';
        addPtr++;
    }
    int length = (int)(A + 25 - addPtr);

    int digitslen = 1;
    digits[0] = 0;
    for (int i = 0; i < length; i++) {
        uint32_t carry = addPtr[i];
        for (int j = 0; j < digitslen; j++) {
            carry += (uint32_t)(digits[j]) << 8;
            digits[j] = (unsigned char)(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            digits[digitslen++] = (unsigned char)(carry % 58);
            carry /= 58;
        }
    }

    // reverse
    for (int i = 0; i < digitslen; i++)
        b58Add[retPos++] = (pszBase58[digits[digitslen - 1 - i]]);

    b58Add[retPos] = 0;
}
// --- END OF FINAL CORRECTED FUNCTION ---
