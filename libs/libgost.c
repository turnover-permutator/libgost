#include "libgost.h"

uint8_t GostCipher64_Permutation[128] = {
    0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1,
    0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf,
    0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0,
    0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb,
    0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc,
    0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0,
    0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7,
    0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2
};

/**
 * @brief Вспомогательная функция, выполняющая базовое зашифровывающее преобразование алгоритма шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма")
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param destination указатель на переменную типа uint64_t для записи закрытого текста
 * @param source указатель на переменную типа uint64_t для чтения открытого текста
 * @return true - успешное зашифрование блока открытого текста
 * @return false - ошибка зашифрования
 */
static bool GostCipher64_EncryptionBlock(GostCipher64_t * cipher, uint64_t * destination, uint64_t * source) {
    uint8_t i, j, k, * p8;
    uint32_t t32, * p32;

    if (cipher == NULL || destination == NULL || source == NULL)
        return false;

    *destination = *source;
    p32 = (uint32_t *) destination;
    p8 = (uint8_t *) (&t32);

    for (i = 0; i < 32; i++) {
        t32 = p32[0];
        if (i < 24)
            t32 += cipher->data.roundKeys[i % 8];
        else
            t32 += cipher->data.roundKeys[7 - (i % 8)];
        for (j = 0; j < 4; j++) {
            p8[j] = (p8[j] & 0xf0) ^ cipher->data.permutation[16*(2*j) + (p8[j] & 0x0f)];
            p8[j] = (p8[j] & 0x0f) ^ (cipher->data.permutation[16*(2*j+1) + ((p8[j] & 0xf0) >> 4)] << 4);
        }
        t32 = ((t32 << 11) ^ ((t32 >> 21) & 0x7FF)) ^ p32[1];
        if (i < 31) {
            p32[1] = p32[0];
            p32[0] = t32;
        }
        else
            p32[1] = t32;
    }

    return true;
}


/**
 * @brief Вспомогательная функция, выполняющая базовое расшифровывающее преобразование алгоритма шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма")
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param destination указатель на переменную типа uint64_t для записи открытого текста
 * @param source указатель на переменную типа uint64_t для чтения закрытого текста
 * @return true - успешное расшифрование закрытого текста,
 * @return false - ошибка расшифрования
 */
static bool GostCipher64_DecryptionBlock(GostCipher64_t * cipher, uint64_t * destination, uint64_t * source) {
    uint8_t i, j, k, * p8;
    uint32_t t32, * p32;

    if (cipher == NULL || destination == NULL || source == NULL)
        return false;

    *destination = *source;
    p32 = (uint32_t *) destination;
    p8 = (uint8_t *) (&t32);

    for (i = 0; i < 32; i++) {
        t32 = p32[0];
        if (i < 8)
            t32 += cipher->data.roundKeys[i % 8];
        else
            t32 += cipher->data.roundKeys[7 - (i % 8)];
        for (j = 0; j < 4; j++) {
            p8[j] = (p8[j] & 0xf0) ^ cipher->data.permutation[16*(2*j) + (p8[j] & 0x0f)];
            p8[j] = (p8[j] & 0x0f) ^ (cipher->data.permutation[16*(2*j+1) + ((p8[j] & 0xf0) >> 4)] << 4);
        }
        t32 = ((t32 << 11) ^ ((t32 >> 21) & 0x7FF)) ^ p32[1];
        if (i < 31) {
            p32[1] = p32[0];
            p32[0] = t32;
        }
        else
            p32[1] = t32;
    }

    return true;
}

bool GostCipher64_Init(GostCipher64_t * cipher) {
    uint8_t i;

    if (cipher == NULL)
        return false;

    cipher->settings.gammaPeriod = 0;
    cipher->settings.IVLength = 0;

    cipher->data.IV = NULL;
    memset(cipher->data.permutation, 0, 128);

    for (i = 0; i < 8; i++)
        cipher->data.roundKeys[i] = 0;

    return true;
}

bool GostCipher64_SetKey(GostCipher64_t * cipher, uint8_t (*key)[32]) {
    uint8_t i;
    uint32_t * p32;

    if (cipher == NULL || key == NULL)
        return false;

    p32 = (uint32_t *)(*key);

    for (i = 0; i < 8; i++)
        cipher->data.roundKeys[i] = p32[8-i-1];

    return true;
}

bool GostCipher64_SetPermutation(GostCipher64_t * cipher, uint8_t (*permutation)[128]) {
    uint8_t i, j, k;
    uint16_t flags;

    if (cipher == NULL || permutation == NULL)
        return false;

    for (i = 0; i < 8; i++) {
        flags = 0;
        for (j = 0; j < 16; j++)
            flags |= (1 << (*permutation)[16*i+j]);
        if (flags != 0xffff)
            return false;
    }

    memcpy(cipher->data.permutation, *permutation, 128);

    return true;
}

bool GostCipher64_SetIV(GostCipher64_t * cipher, uint8_t *IV, uint8_t length) {
    if (cipher == NULL || IV == NULL)
        return false;

    if (cipher->data.IV != NULL)
        free(cipher->data.IV);
    cipher->data.IV = (uint8_t*) malloc(length * sizeof(uint8_t));
    memcpy(cipher->data.IV, IV, length);
    cipher->settings.IVLength = length;

    return true;
}

bool GostCipher64_SetGammaPeriod(GostCipher64_t * cipher, uint8_t period) {
    if (cipher == NULL)
        return false;
    if (period == 0 || period > 8)
        return false;

    cipher->settings.gammaPeriod = period;

    return true;
}

bool GostCipher64_EncryptionECB(GostCipher64_t * cipher, uint8_t * destination, uint8_t * source, size_t length) {
    uint64_t block, * d64, * s64;
    size_t i;

    if (cipher == NULL || destination == NULL || source == NULL)
        return false;

    if (length == 0 || length % 8 != 0)
        return false;

    d64 = (uint64_t *) destination;
    s64 = (uint64_t *) source;

    for (i = 0; i < length; i += 8) {
        block = s64[i/8];
        if (!GostCipher64_EncryptionBlock(cipher, &block, &block))
            return false;
        d64[i/8] = block;
    }

    return true;
}

bool GostCipher64_DecryptionECB(GostCipher64_t * cipher, uint8_t * destination, uint8_t * source, size_t length) {
    uint64_t block, * d64, * s64;
    size_t i;

    if (cipher == NULL || destination == NULL || source == NULL)
        return false;

    if (length == 0 || length % 8 != 0)
        return false;

    d64 = (uint64_t *) destination;
    s64 = (uint64_t *) source;

    for (i = 0; i < length; i += 8) {
        block = s64[i/8];
        if (!GostCipher64_DecryptionBlock(cipher, &block, &block))
            return false;
        d64[i/8] = block;
    }

    return true;
}

bool GostCipher64_EncryptionCTR(GostCipher64_t * cipher, uint8_t * destination, uint8_t * source, size_t length) {
    size_t i;
    uint8_t * p8;
    uint64_t counter, gamma;

    if (cipher == NULL || destination == NULL || source == NULL || length == 0)
        return false;

    if (cipher->settings.IVLength != 4)
        return false;

    p8 = (uint8_t *) (&gamma);
    counter = 0;
    memcpy(((uint8_t *) (&counter)) + 4, cipher->data.IV, cipher->settings.IVLength);

    for (i = 0; i < length; i++) {
        if (i % 8 == 0) {
            GostCipher64_EncryptionBlock(cipher, &gamma, &counter);
            counter++;
        }
        destination[i] = source[i] ^ p8[i % 8];
    }

    return true;
}

bool GostCipher64_DecryptionCTR(GostCipher64_t * cipher, uint8_t * destination, uint8_t * source, size_t length) {
    return GostCipher64_EncryptionCTR(cipher, destination, source, length);
}

bool GostCipher64_ControlECB() {
    GostCipher64_t cipher;

    uint8_t key[32] = {
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t open[32] = {
        0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
        0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
        0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
        0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89
    };

    uint8_t close[32] = {
        0xa0, 0x72, 0xf3, 0x94, 0x04, 0x3f, 0x07, 0x2b,
        0x48, 0x6e, 0x55, 0xd3, 0x15, 0xe7, 0x70, 0xde,
        0x1e, 0xbc, 0xcf, 0xea, 0xe9, 0xd9, 0xd8, 0x11,
        0xfb, 0x7e, 0xc6, 0x96, 0x09, 0x26, 0x68, 0x7c
    };

    uint8_t result[32] = { 0 };

    if (!GostCipher64_Init(&cipher))
        return false;
    if (!GostCipher64_SetKey(&cipher, &key))
        return false;
    if (!GostCipher64_SetPermutation(&cipher, &GostCipher64_Permutation))
        return false;

    if (!GostCipher64_EncryptionECB(&cipher, result, open, 32))
        return false;
    if (!memcmp(result, close, 32))
        return false;

    if (!GostCipher64_DecryptionECB(&cipher, result, close, 32))
        return false;
    if (!memcmp(result, open, 32))
        return false;

    return true;
}

bool GostCipher64_ControlCTR() {
    GostCipher64_t cipher;

    uint8_t key[32] = {
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t IV[4] = { 0x78, 0x56, 0x34, 0x12 };

    uint8_t open[32] = {
        0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
        0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
        0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
        0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89
    };

    uint8_t close[32] = {
        0x3c, 0xb9, 0xb7, 0x97, 0x0c, 0x11, 0x98, 0x4e,
        0x69, 0x5d, 0xe8, 0xd6, 0x93, 0x0d, 0x25, 0x3e,
        0xef, 0xdb, 0xb2, 0x07, 0x88, 0x86, 0x6d, 0x13,
        0x2d, 0xa1, 0x52, 0xab, 0x80, 0xb6, 0x8e, 0x56
    };

    uint8_t result[32] = { 0 };

    if (!GostCipher64_Init(&cipher))
        return false;
    if (!GostCipher64_SetKey(&cipher, &key))
        return false;
    if (!GostCipher64_SetPermutation(&cipher, &GostCipher64_Permutation))
        return false;
    if (!GostCipher64_SetIV(&cipher, IV, 4))
        return false;
    if (!GostCipher64_SetGammaPeriod(&cipher, 8))
        return false;

    if (!GostCipher64_EncryptionCTR(&cipher, result, open, 32))
        return false;
    if (!memcmp(result, close, 32))
        return false;


    if (!GostCipher64_DecryptionCTR(&cipher, result, close, 32))
        return false;
    if (!memcmp(result, open, 32))
        return false;

    return true;
}