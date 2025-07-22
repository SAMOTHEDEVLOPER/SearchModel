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

#include "Base58.h"

#include <vector>
#include <string>
#include <string.h>
#include <cstdint>

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char *pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t b58digits_map[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
};

bool DecodeBase58(const char *psz, std::vector<uint8_t> &vch)
{
    // Skip and count leading '1's (which correspond to leading 0-bytes)
    int zeroes = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }

    // Allocate enough space in big-endian base256 representation.
    // Each Base58 digit carries log2(58) = 5.85 bits of information, so
    // a N-char string will be roughly N * 5.85 / 8 bytes.
    // A pessimistic estimate is N * 77 / 100.
    size_t length = strlen(psz);
    std::vector<uint8_t> b256(length * 77 / 100 + 1, 0); // Initialize with zeroes

    // Process the characters.
    for (size_t i = 0; i < length; i++) {
        // Decode base58 character
        if (psz[i] & 0x80) // High-bit set on invalid character
            return false;

        int8_t c = b58digits_map[static_cast<uint8_t>(psz[i])];
        if (c < 0) // Invalid character
            return false;

        // Apply "b256 = b256 * 58 + c"
        uint32_t carry = static_cast<uint32_t>(c);
        for (size_t j = 0; j < b256.size(); ++j) {
            size_t k = b256.size() - 1 - j; // Process from right to left
            carry += static_cast<uint32_t>(b256[k]) * 58;
            b256[k] = static_cast<uint8_t>(carry % 256);
            carry /= 256;
        }
        
        // Should be fully carried, but as a precaution
        if(carry != 0) return false;
    }

    // Skip leading zeroes in b256.
    auto it = b256.begin();
    while (it != b256.end() && *it == 0) {
        it++;
    }
    
    // Copy result into output vector.
    vch.clear();
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00); // Prepend leading zero bytes
    vch.insert(vch.end(), it, b256.end());

    return true;
}

std::string EncodeBase58(const unsigned char *pbegin, const unsigned char *pend)
{
    // Skip and count leading zeroes.
    int zeroes = 0;
    const unsigned char *p = pbegin;
    while (p != pend && *p == 0) {
        p++;
        zeroes++;
    }
    
    // Allocate enough space in big-endian base58 representation.
    // Each byte requires log58(256) = 1.365 digits, so a N-byte input will be
    // roughly N * 1.365 characters long.
    // A pessimistic estimate is N * 137 / 100.
    size_t size = (pend - p) * 137 / 100 + 1;
    std::vector<uint8_t> b58(size, 0);

    // Process the bytes.
    while (p != pend) {
        // Apply "b58 = b58 * 256 + *p"
        uint32_t carry = *p;
        for (size_t i = 0; i < b58.size(); i++) {
            size_t k = b58.size() - 1 - i; // Process from right to left
            carry += static_cast<uint32_t>(b58[k]) * 256;
            b58[k] = static_cast<uint8_t>(carry % 58);
            carry /= 58;
        }
        
        // Should be fully carried
        if(carry != 0) return ""; // Error

        p++;
    }

    // Skip leading zeroes in b58.
    auto it = b58.begin();
    while (it != b58.end() && *it == 0) {
        it++;
    }

    // Build the final string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end()) {
        str += pszBase58[*it];
        it++;
    }

    return str;
}


// Wrapper functions
std::string EncodeBase58(const std::vector<unsigned char> &vch)
{
    return EncodeBase58(vch.data(), vch.data() + vch.size());
}

bool DecodeBase58(const std::string &str, std::vector<unsigned char> &vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}
