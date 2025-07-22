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
    //    [0]       = version byte
    //    [1..20]   = 160-bit hash
    //    [21..24]  = 4-byte checksum
    unsigned char A[25];

    // --- Checksum Calculation ---
    // The checksum is the first 4 bytes of SHA256(SHA256(version + hash160)).

    // Step 1: Prepare the first 21-byte message (version + hash).
    // The hash from the previous step is already in the correct byte order in the `hash` buffer.
    unsigned char first_sha_input[21];
    first_sha_input[0] = 0x00; // Version byte for P2PKH
    memcpy(first_sha_input + 1, hash, 20);

    // Step 2: Calculate the first SHA256 hash.
    unsigned char first_sha_output[32];
    SHA256(first_sha_input, 21, first_sha_output);

    // Step 3: Calculate the second SHA256 hash on the result of the first.
    unsigned char second_sha_output[32];
    SHA256(first_sha_output, 32, second_sha_output);

    // Step 4: The checksum is the first 4 bytes of the second hash.
    // Assemble the final 25-byte payload for Base58 encoding.
    A[0] = 0x00;
    memcpy(A + 1, hash, 20);
    memcpy(A + 21, second_sha_output, 4);

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
    for (int i = 0; i < dataSize; i++) {
        unsigned int carry = addPtr[i];
        for (int j = 0; j < length; j++) {
            carry += (unsigned int)(digits[j]) << 8; // Multiply by 256
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
        b58Add[retPos + length - 1 - i] = pszBase58[digits[i]];
    }

    b58Add[retPos + length] = 0; // Null-terminate the string.
}
// --- END OF FIXED FUNCTION ---
