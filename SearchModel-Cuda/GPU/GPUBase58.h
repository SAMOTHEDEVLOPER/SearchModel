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
    unsigned char digits[128]; // Buffer for Base58 conversion

    // --- Checksum Calculation (Corrected Logic) ---
    uint32_t s[8]; // SHA256 state
    uint32_t chunk[16]; // 64-byte chunk for transform

    // Step 1: First hash of (0x00 || 20-byte hash)
    // The message is 21 bytes. We must pad it for SHA256.
    unsigned char first_sha_input[21];
    first_sha_input[0] = 0x00;
    memcpy(first_sha_input + 1, (unsigned char*)hash, 20);

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, first_sha_input, 21);
    sha256_final(&ctx, (unsigned char*)s); // s now holds the first hash result (32 bytes)

    // Step 2: Second hash of the 32-byte result from the first hash
    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char*)s, 32);
    sha256_final(&ctx, (unsigned char*)chunk); // chunk now holds the final hash

    // Step 3: Assemble the 25-byte address payload
    A[0] = 0x00;
    memcpy(A + 1, (unsigned char*)hash, 20);
    memcpy(A + 21, (unsigned char*)chunk, 4); // Checksum is the first 4 bytes of the final hash

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
