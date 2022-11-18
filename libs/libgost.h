#ifndef LIBGOST
#define LIBGOST

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/**
 * @brief Узел замены, определённый в тексте ГОСТ Р 34.12-2015 для алгоритма шифрования с размером блока 64 бит ("Магма")
 */
extern uint8_t GostCipher64_Permutation[128];


/**
 * @brief Структурный тип данных, описывающий алгоритм шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма")
 */
typedef struct {
    struct {
        uint8_t   permutation[128];
        uint32_t  roundKeys[8];
        uint8_t * IV;
    } data;
    struct {
        uint8_t   IVLength;
        uint8_t   gammaPeriod;
    } settings;
} GostCipher64_t;


/**
 * @brief Функция инициализации алгоритма шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма")
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @return true - успешная инициализация полей структуры,
 * @return false - ошибка инициализации
 */
bool GostCipher64_Init(GostCipher64_t * cipher);


/**
 * @brief Функция установки узла замены в алгоритме шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма")
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param permutation указатель на байтовый массив из 128 элементов
 * @return true -успешная установка узла замены,
 * @return false - ошибка установки
 */
bool GostCipher64_SetPermutation(GostCipher64_t * cipher, uint8_t (*permutation)[128]);


/**
 * @brief Функция установки симметричного ключа и последующей выработки раундовых ключей в алгоритме шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма")
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param key указатель на байтовый массив из 32 элементов
 * @return true - успешная установка симметричного ключа,
 * @return false - ошибка установки
 */
bool GostCipher64_SetKey(GostCipher64_t * cipher, uint8_t (*key)[32]);


/**
 * @brief Функция установки вектора инициализации в алгоритме шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма")
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param IV указатель на байтовый массив
 * @param length размер массива в байтах
 * @return true - успешна установка вектора инициализации,
 * @return false - ошибка установки
 */
bool GostCipher64_SetIV(GostCipher64_t * cipher, uint8_t *IV, uint8_t length);


/**
 * @brief Функция установки длины вырабатываемой гаммы в алгоритме шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма")
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param period значение периода гаммы в байтах
 * @return true - успешная установка периода гаммы,
 * @return false - ошибка установки
 */
bool GostCipher64_SetGammaPeriod(GostCipher64_t * cipher, uint8_t period);


/**
 * @brief Функция, выполняющая зашифрование в режиме простой замены (ECB) по алгоритму шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма") в соответствии с ГОСТ Р 34.13-2015
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param destination указатель на байтовый массив для записи закрытого текста
 * @param source указатель на байтовый массив для чтения открытого текста
 * @param length размер массивов в байтах
 * @return true - успешное зашифрование открытого текста в режиме простой замены (ECB)
 * @return false - ошибка зашифрования
 */
bool GostCipher64_EncryptionECB(GostCipher64_t * cipher, uint8_t * destination, uint8_t * source, size_t length);


/**
 * @brief Функция, выполняющая расшифрование в режиме простой замены (ECB) по алгоритму шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма") в соответствии с ГОСТ Р 34.13-2015
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param destination указатель на байтовый массив для записи открытого текста
 * @param source указатель на байтовый массив для чтения закрытого текста
 * @param length размер массивов в байтах
 * @return true - успешное расшифрование открытого текста в режиме простой замены (ECB)
 * @return false - ошибка расшифрования
 */
bool GostCipher64_DecryptionECB(GostCipher64_t * cipher, uint8_t * destination, uint8_t * source, size_t length);


/**
 * @brief Функция, выполняющая зашифрование в режиме гаммирования (CTR) по алгоритму шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма") в соответствии с ГОСТ Р 34.13-2015
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param destination указатель на байтовый массив для записи закрытого текста
 * @param source указатель на байтовый массив для чтения открытого текста
 * @param length размер массивов в байтах
 * @return true - успешное расшифрование открытого текста в режиме простой замены (ECB)
 * @return false - ошибка расшифрования
 */
bool GostCipher64_EncryptionCTR(GostCipher64_t * cipher, uint8_t * destination, uint8_t * source, size_t length);


/**
 * @brief Функция, выполняющая расшифрование в режиме гаммирования (CTR) по алгоритму шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма") в соответствии с ГОСТ Р 34.13-2015
 *
 * @param cipher указатель на структуру GostCipher64_t
 * @param destination указатель на байтовый массив для записи открытого текста
 * @param source указатель на байтовый массив для чтения закрытого текста
 * @param length размер массивов в байтах
 * @return true - успешное расшифрование открытого текста в режиме простой замены (ECB)
 * @return false - ошибка расшифрования
 */
bool GostCipher64_DecryptionCTR(GostCipher64_t * cipher, uint8_t * destination, uint8_t * source, size_t length);


/**
 * @brief Функция для проверки функционирования алгоритма шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма"), работающего в режиме простой замены (ECB), на контрольных примерах из текста ГОСТ Р 34.13-2015
 *
 * @return true - успешная проверка
 * @return false - ошибка при проверке
 */
bool GostCipher64_ControlECB();


/**
 * @brief Функция для проверки функционирования алгоритма шифрования ГОСТ Р 34.12-2015 с размером блока 64 бит ("Магма"), работающего в режиме гаммирования (CTR), на контрольных примерах из текста ГОСТ Р 34.13-2015
 *
 * @return true - успешная проверка
 * @return false - ошибка при проверке
 */
bool GostCipher64_ControlCTR();

#endif