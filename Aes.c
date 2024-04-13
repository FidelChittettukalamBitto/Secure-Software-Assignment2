
/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */
#include <stdlib.h>
#include "rijndael.h"

// S-box table for SubBytes operation
unsigned char s_box[256] = {
    // S-box values from the original code
};

// Inverse S-box table for InvertSubBytes operation
unsigned char inv_s[256] = {
    // Inverse S-box values from the original code
};

// Rcon table for key expansion
unsigned char rcon[AES_SIZE] = {
    // Rcon values from the original code
};

// SubBytes operation
void sub_bytes(unsigned char *block) {
    for (int i = 0; i < AES_SIZE; i++) {
        block[i] = s_box[block[i]];
    }
}

// ShiftRows operation
void shift_rows(unsigned char *block) {
    unsigned char temp_block[AES_SIZE];
    for (int i = 0; i < AES_SIZE; i += 4) {
        temp_block[i] = block[i];
        temp_block[(i + 1) % AES_SIZE] = block[i + 1];
        temp_block[(i + 2) % AES_SIZE] = block[i + 2];
        temp_block[(i + 3) % AES_SIZE] = block[i + 3];
    }
    for (int i = 0; i < AES_SIZE; i++) {
        block[i] = temp_block[i];
    }
}

// MixColumns operation
void mix_columns(unsigned char *block) {
    unsigned char temp_block[AES_SIZE];
    for (int i = 0; i < AES_SIZE; i += 4) {
        temp_block[i] = gmul(block[i], 0x02) ^ gmul(block[i + 1], 0x03) ^ block[i + 2] ^ block[i + 3];
        temp_block[i + 1] = block[i] ^ gmul(block[i + 1], 0x02) ^ gmul(block[i + 2], 0x03) ^ block[i + 3];
        temp_block[i + 2] = block[i] ^ block[i + 1] ^ gmul(block[i + 2], 0x02) ^ gmul(block[i + 3], 0x03);
        temp_block[i + 3] = gmul(block[i], 0x03) ^ block[i + 1] ^ block[i + 2] ^ gmul(block[i + 3], 0x02);
    }
    for (int i = 0; i < AES_SIZE; i++) {
        block[i] = temp_block[i];
    }
}

// InvertSubBytes operation
void invert_sub_bytes(unsigned char *block) {
    for (int i = 0; i < AES_SIZE; i++) {
        block[i] = inv_s[block[i]];
    }
}

// InvertShiftRows operation
void invert_shift_rows(unsigned char *block) {
    unsigned char temp_block[AES_SIZE];
    for (int i = 0; i < AES_SIZE; i += 4) {
        temp_block[i] = block[i];
        temp_block[(i + 1) % AES_SIZE] = block[(i + 13) % AES_SIZE];
        temp_block[(i + 2) % AES_SIZE] = block[(i + 10) % AES_SIZE];
        temp_block[(i + 3) % AES_SIZE] = block[(i + 7) % AES_SIZE];
    }
    for (int i = 0; i < AES_SIZE; i++) {
        block[i] = temp_block[i];
    }
}

// InvertMixColumns operation
void invert_mix_columns(unsigned char *block) {
    unsigned char temp_block[AES_SIZE];
    for (int i = 0; i < AES_SIZE; i += 4) {
        temp_block[i] = gmul(block[i], 0x0e) ^ gmul(block[i + 1], 0x0b) ^ gmul(block[i + 2], 0x0d) ^ gmul(block[i + 3], 0x09);
        temp_block[i + 1] = gmul(block[i], 0x09) ^ gmul(block[i + 1], 0x0e) ^ gmul(block[i + 2], 0x0b) ^ gmul(block[i + 3], 0x0d);
        temp_block[i + 2] = gmul(block[i], 0x0d) ^ gmul(block[i + 1], 0x09) ^ gmul(block[i + 2], 0x0e) ^ gmul(block[i + 3], 0x0b);
        temp_block[i + 3] = gmul(block[i], 0x0b) ^ gmul(block[i + 1], 0x0d) ^ gmul(block[i + 2], 0x09) ^ gmul(block[i + 3], 0x0e);
    }
    for (int i = 0; i < AES_SIZE; i++) {
        block[i] = temp_block[i];
    }
}

// AddRoundKey operation
void add_round_key(unsigned char *block, unsigned char *round_key) {
    for (int i = 0; i < AES_SIZE; i++) {
        block[i] ^= round_key[i];
    }
}

// KeyExpansion operation
unsigned char *expand_key(unsigned char *cipher_key) {
    unsigned char *expanded_keys = (unsigned char *)malloc(sizeof(unsigned char
