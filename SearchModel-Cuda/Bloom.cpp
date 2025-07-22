#include "Bloom.h"
#include <iostream>
#include <math.h>
#include <string.h>

#define MAKESTRING(n) STRING(n)
#define STRING(n) #n
#define BLOOM_MAGIC "libbloom2"
#define BLOOM_VERSION_MAJOR 2
#define BLOOM_VERSION_MINOR 1

Bloom::Bloom(unsigned long long entries, double error) : _ready(0)
{
    if (entries < 2 || error <= 0 || error >= 1) {
        printf("Bloom init error, minimum 2 entries required\n");
        return;
    }

    _entries = entries;
    _error = error;

    long double num = -log(_error);
    long double denom = 0.480453013918201; // ln(2)^2
    _bpe = (num / denom);

    long double dentries = (long double)_entries;
    long double allbits = dentries * _bpe;
    _bits = (unsigned long long int)allbits;

    if (_bits % 8) {
        _bytes = (unsigned long long int)(_bits / 8) + 1;
    } else {
        _bytes = (unsigned long long int) _bits / 8;
    }

    _hashes = (unsigned char)ceil(0.693147180559945 * _bpe);  // ln(2)

    _bf = (unsigned char *)calloc((unsigned long long int)_bytes, sizeof(unsigned char));
    if (_bf == NULL) {
        printf("Bloom init error\n");
        return;
    }

    _ready = 1;

    _major = BLOOM_VERSION_MAJOR;
    _minor = BLOOM_VERSION_MINOR;
}

Bloom::~Bloom()
{
    if (_ready)
        free(_bf);
}

int Bloom::check(const void *buffer, int len)
{
    return bloom_check_add(buffer, len, 0);
}


int Bloom::add(const void *buffer, int len)
{
    return bloom_check_add(buffer, len, 1);
}


void Bloom::print()
{
    printf("Bloom at %p\n", (void *)this);
    if (!_ready) {
        printf(" *** NOT READY ***\n");
    }
    printf("  Version    : %d.%d\n", _major, _minor);
    printf("  Entries    : %llu\n", _entries);
    printf("  Error      : %1.10f\n", _error);
    printf("  Bits       : %llu\n", _bits);
    printf("  Bits/Elem  : %f\n", _bpe);
    printf("  Bytes      : %llu", _bytes);
    unsigned int KB = _bytes / 1024;
    unsigned int MB = KB / 1024;
    printf(" (%u MB)\n", MB);
    printf("  Hash funcs : %d\n", _hashes);
}


int Bloom::reset()
{
    if (!_ready)
        return 1;
    memset(_bf, 0, _bytes);
    return 0;
}

// NOTE: Save/Load functions are commented out as they are non-portable (use Unix-specific calls)
// and have logical flaws (writing raw pointer values). They would need to be rewritten
// with standard file I/O (fopen, fwrite) and proper serialization to be safe and portable.
int Bloom::save(const char *filename)
{
    return 0;
}

int Bloom::load(const char *filename)
{
    return 0;
}


unsigned char Bloom::get_hashes()
{
    return _hashes;
}
unsigned long long int Bloom::get_bits()
{
    return _bits;
}
unsigned long long int Bloom::get_bytes()
{
    return _bytes;
}
const unsigned char *Bloom::get_bf()
{
    return _bf;
}

int Bloom::test_bit_set_bit(unsigned char *buf, unsigned int bit, int set_bit)
{
    // Check if the requested bit is within the bounds of the filter
    if (bit >= _bits) {
        // This case should ideally not be reached if the modulo in bloom_check_add is correct,
        // but it's a good safeguard.
        return 1; // Treat as a "hit" to be safe, preventing a buffer over-read.
    }
    
    unsigned int byte = bit >> 3; // Same as bit / 8
    unsigned char c = buf[byte];        // expensive memory access
    unsigned char mask = 1 << (bit % 8);

    if (c & mask) {
        return 1;
    } else {
        if (set_bit) {
            buf[byte] = c | mask;
        }
        return 0;
    }
}

int Bloom::bloom_check_add(const void *buffer, int len, int add)
{
    if (_ready == 0) {
        printf("bloom not initialized!\n");
        return -1;
    }

    unsigned char hits = 0;
    unsigned int a = murmurhash2(buffer, len, 0x9747b28c);
    unsigned int b = murmurhash2(buffer, len, a);
    unsigned int x;
    unsigned char i;

    for (i = 0; i < _hashes; i++) {
        x = (a + b * i) % _bits;
        if (test_bit_set_bit(_bf, x, add)) {
            hits++;
        } else if (!add) {
            // If we're only checking, and we find a bit that's not set,
            // we can exit early. The element is definitely not in the filter.
            return 0;
        }
    }

    if (hits == _hashes) {
        // If we're checking, this means all bits were set, so it's a possible match.
        // If we're adding, this means all bits were already set before this add.
        return 1;
    }

    return 0;
}


// MurmurHash2, by Austin Appleby (modified to be endian-safe)
unsigned int Bloom::murmurhash2(const void *key, int len, const unsigned int seed)
{
    const unsigned int m = 0x5bd1e995;
    const int r = 24;

    unsigned int h = seed ^ len;

    const unsigned char *data = (const unsigned char *)key;

    while (len >= 4) {
        // Read 4 bytes one by one into an unsigned int in a defined (little-endian) order
        unsigned int k = data[0];
        k |= (unsigned int)data[1] << 8;
        k |= (unsigned int)data[2] << 16;
        k |= (unsigned int)data[3] << 24;

        k *= m;
        k ^= k >> r;
        k *= m;

        h *= m;
        h ^= k;

        data += 4;
        len -= 4;
    }

    // Handle the last few bytes of the input array
    switch (len) {
    case 3:
        h ^= (unsigned int)data[2] << 16;
        // fallthrough
    case 2:
        h ^= (unsigned int)data[1] << 8;
        // fallthrough
    case 1:
        h ^= (unsigned int)data[0];
        h *= m;
    };

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
}
