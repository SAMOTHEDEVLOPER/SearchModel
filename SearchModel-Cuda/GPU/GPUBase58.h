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


// --- START OF FIXED FUNCTION ---
__device__ __noinline__ void _GetAddress(int type, uint32_t *hash, char *b58Add)
{
    // A: a 25-byte array to hold the version, hash, and checksum.
    unsigned char A[25];
    uint32_t s[8]; // State for SHA256

    // --- Checksum Calculation ---
    // The checksum is the first 4 bytes of SHA256(SHA256(version + hash160)).

    // Step 1: Prepare the first 21-byte message (0x00 + hash160) for SHA256.
    // SHA256 operates on 512-bit (64-byte) blocks. We need to pad the message.
    uint32_t first_sha_input[16];
    
    // The `hash` input is already in little-endian uint32_t[] format.
    // We construct the first 21 bytes: 0x00, then the 20 bytes of the hash.
    first_sha_input[0] = (0x00 << 24) | (hash[0] & 0x00FFFFFF);
    first_sha_input[1] = (hash[0] >> 24) | ((hash[1] & 0x0000FFFF) << 8);
    first_sha_input[2] = (hash[1] >> 16) | ((hash[2] & 0x000000FF) << 16);
    first_sha_input[3] = (hash[2] >> 8);
    first_sha_input[4] = hash[3];
    first_sha_input[5] = (hash[4] & 0xFFFFFF00) | 0x00000080; // Last byte of hash + padding
    
    // Zero out the rest of the block and set the length.
    // The message is 21 bytes = 168 bits.
    for (int i = 6; i < 15; i++) {
        first_sha_input[i] = 0;
    }
    first_sha_input[15] = 168; // Length in bits, already endian-swapped for SHA256

    // Calculate the first SHA256 hash.
    SHA256Initialize(s);
    SHA256Transform(s, first_sha_input);

    // Step 2: Prepare the second SHA256 hash. The input is the 32-byte output of the first hash.
    // The state `s` already holds the hash in the correct format. We just need to pad it.
    uint32_t second_sha_input[16];
    for(int i = 0; i < 8; i++) {
        second_sha_input[i] = s[i];
    }
    second_sha_input[8] = 0x80000000; // Padding
    for (int i = 9; i < 15; i++) {
        second_sha_input[i] = 0;
    }
    second_sha_input[15] = 256; // Length is 32 bytes = 256 bits

    // Calculate the second SHA256 hash.
    SHA256Initialize(s);
    SHA256Transform(s, second_sha_input);

    // Step 3: The checksum is the first 4 bytes of the second hash.
    // The first word s[0] contains these bytes. We need to get them in big-endian order.
    // The SHA256 transform already produces big-endian output in the state words.
    unsigned char checksum[4];
    checksum[0] = (s[0] >> 24) & 0xFF;
    checksum[1] = (s[0] >> 16) & 0xFF;
    checksum[2] = (s[0] >> 8) & 0xFF;
    checksum[3] = s[0] & 0xFF;

    // Assemble the final 25-byte payload for Base58 encoding.
    A[0] = 0x00;
    memcpy(A + 1, (unsigned char*)hash, 20);
    memcpy(A + 21, checksum, 4);

    // --- Base58 Encoding ---
    
    unsigned char *addPtr = A;
    int dataSize = 25;
    int retPos = 0;
    unsigned char digits[128]; // This buffer is large enough for a 25-byte number.

    // Count and encode leading zeroes as '1's.
    for (int i = 0; i < dataSize && addPtr[i] == 0; i++) {
        b58Add[retPos++] = '1';
    }

    int length = 0; // Length of the b58 number
    
    // Convert base256 to base58.
    for (int i = retPos; i < dataSize; i++) {
        unsigned int carry = addPtr[i];
        for (int j = 0; j < length; j++) {
            carry += (unsigned int)(digits[j]) * 256;
            digits[j] = (unsigned char)(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            digits[length++] = (unsigned char)(carry % 58);
            carry /= 58;
        }
    }
    
    // The number of leading '1's has already been written.
    // Now write the rest of the b58 digits in reverse order.
    for(int i = 0; i < length; i++) {
        b58Add[retPos++] = pszBase58[digits[length - 1 - i]];
    }

    b58Add[retPos] = 0; // Null-terminate the string.
}
// --- END OF FIXED FUNCTION ---
