/*
 * WPA Supplicant / Empty template functions for crypto wrapper
 * Copyright (c) 2005, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto.h"

#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AESGCM
#define HAVE_AES_KEYWRAP
#define WOLFSSL_SHA512
#define WOLFSSL_CMAC
#define HAVE_ECC
#define USE_FAST_MATH
#define WOLFSSL_KEY_GEN

#include <wolfssl/options.h>
/* wolfSSL headers */
#include <wolfssl/wolfcrypt/md4.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/openssl/bn.h>


#ifndef CONFIG_FIPS
int md4_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    Md4    md4;
    size_t i;

    wc_InitMd4(&md4);

    for (i = 0; i < num_elem; i++)
        wc_Md4Update(&md4, addr[i], len[i]);

    wc_Md4Final(&md4, mac);

    return 0;
}
#endif

#ifndef CONFIG_FIPS
int md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    Md5    md5;
    size_t i;

    wc_InitMd5(&md5);

    for (i = 0; i < num_elem; i++)
        wc_Md5Update(&md5, addr[i], len[i]);

    wc_Md5Final(&md5, mac);

    return 0;
}
#endif

int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len,
        u8 *mac)
{
    Sha    sha;
    size_t i;

    wc_InitSha(&sha);

    for (i = 0; i < num_elem; i++)
        wc_ShaUpdate(&sha, addr[i], len[i]);

    wc_ShaFinal(&sha, mac);

    return 0;
}

#ifndef NO_SHA256_WRAPPER
int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len,
          u8 *mac)
{
    Sha256 sha256;
    size_t i;

    wc_InitSha256(&sha256);

    for (i = 0; i < num_elem; i++)
        wc_Sha256Update(&sha256, addr[i], len[i]);

    wc_Sha256Final(&sha256, mac);

    return 0;
}
#endif /* NO_SHA256_WRAPPER */

static int wolfssl_hmac_vector(int type, const u8 *key,
                               size_t key_len, size_t num_elem,
                               const u8 *addr[], const size_t *len, u8 *mac,
                               unsigned int mdlen)
{
    Hmac hmac;
    size_t i;

    (void)mdlen;

    if (wc_HmacSetKey(&hmac, type, key, (word32)key_len) != 0)
        return -1;
    for (i = 0; i < num_elem; i++)
            if (wc_HmacUpdate(&hmac, addr[i], len[i]) != 0)
                return -1;
    if (wc_HmacFinal(&hmac, mac) != 0)
        return -1;
    return 0;
}

#ifndef CONFIG_FIPS

int hmac_md5_vector(const u8 *key, size_t key_len, size_t num_elem,
                    const u8 *addr[], const size_t *len, u8 *mac)
{
    return wolfssl_hmac_vector(MD5, key, key_len, num_elem, addr, len, mac, 16);
}


int hmac_md5(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
             u8 *mac)
{
    return hmac_md5_vector(key, key_len, 1, &data, &data_len, mac);
}

#endif /* CONFIG_FIPS */

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
                     const u8 *addr[], const size_t *len, u8 *mac)
{
        return wolfssl_hmac_vector(SHA, key, key_len, num_elem, addr,
                                   len, mac, 20);
}


int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
               u8 *mac)
{
        return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}

#ifdef CONFIG_SHA256

int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
                       const u8 *addr[], const size_t *len, u8 *mac)
{
    return wolfssl_hmac_vector(SHA256, key, key_len, num_elem, addr, len, mac,
                               32);
}


int hmac_sha256(const u8 *key, size_t key_len, const u8 *data,
                size_t data_len, u8 *mac)
{
    return hmac_sha256_vector(key, key_len, 1, &data, &data_len, mac);
}

#endif /* CONFIG_SHA256 */


#ifdef CONFIG_SHA384

int hmac_sha384_vector(const u8 *key, size_t key_len, size_t num_elem,
                       const u8 *addr[], const size_t *len, u8 *mac)
{
    return wolfssl_hmac_vector(SHA384, key, key_len, num_elem, addr, len, mac,
                               48);
}


int hmac_sha384(const u8 *key, size_t key_len, const u8 *data,
                size_t data_len, u8 *mac)
{
    return hmac_sha384_vector(key, key_len, 1, &data, &data_len, mac);
}

#endif /* CONFIG_SHA384 */

int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len,
                int iterations, u8 *buf, size_t buflen)
{
        if (wc_PBKDF2(buf, (const byte*)passphrase, os_strlen(passphrase), ssid,
                      ssid_len, iterations, buflen, SHA) != 0)
                return -1;
        return 0;
}


#ifdef CONFIG_DES
void des_encrypt(const u8 *clear, const u8 *key, u8 *cypher)
{
    Des des;
    u8  pkey[8], next, tmp;
    int i;

    /* Add parity bits to the key */
    next = 0;
    for (i = 0; i < 7; i++) {
        tmp = key[i];
        pkey[i] = (tmp >> i) | next | 1;
        next = tmp << (7 - i);
    }
    pkey[i] = next | 1;

    wc_Des_SetKey(&des, pkey, NULL, DES_ENCRYPTION);
    wc_Des_EcbEncrypt(&des, cypher, clear, DES_BLOCK_SIZE);
}
#endif


void * aes_encrypt_init(const u8 *key, size_t len)
{
    Aes* aes;

    aes = os_malloc(sizeof(Aes));
    if (aes == NULL)
        return NULL;

    if (wc_AesSetKey(aes, key, len, NULL, AES_ENCRYPTION) < 0) {
        os_free(aes);
        return NULL;
    }

    return aes;
}

void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt)
{
    wc_AesEncryptDirect((Aes*)ctx, crypt, plain);
}


void aes_encrypt_deinit(void *ctx)
{
    if (ctx != NULL)
        os_free(ctx);
}


void* aes_decrypt_init(const u8 *key, size_t len)
{
    Aes* aes;

    aes = os_malloc(sizeof(Aes));
    if (aes == NULL)
        return NULL;

    if (wc_AesSetKey(aes, key, len, NULL, AES_DECRYPTION) < 0) {
        os_free(aes);
        return NULL;
    }

    return aes;
}


void aes_decrypt(void *ctx, const u8 *crypt, u8 *plain)
{
    wc_AesDecryptDirect((Aes*)ctx, plain, crypt);
}


void aes_decrypt_deinit(void *ctx)
{
    if (ctx != NULL)
        os_free(ctx);
}

int crypto_mod_exp(const u8 *base, size_t base_len,
                   const u8 *power, size_t power_len,
                   const u8 *modulus, size_t modulus_len,
                   u8 *result, size_t *result_len)
{
	BIGNUM *bn_base, *bn_exp, *bn_modulus, *bn_result;
	int ret = -1;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		return -1;

	bn_base = BN_bin2bn(base, base_len, NULL);
	bn_exp = BN_bin2bn(power, power_len, NULL);
	bn_modulus = BN_bin2bn(modulus, modulus_len, NULL);
	bn_result = BN_new();

	if (bn_base == NULL || bn_exp == NULL || bn_modulus == NULL ||
	    bn_result == NULL)
		goto error;

	if (BN_mod_exp(bn_result, bn_base, bn_exp, bn_modulus, ctx) != 1)
		goto error;

	*result_len = BN_bn2bin(bn_result, result);
	ret = 0;

 error:
	BN_free(bn_base);
	BN_free(bn_exp);
	BN_free(bn_modulus);
	BN_free(bn_result);
	BN_CTX_free(ctx);
	return ret;
}

int aes_128_cbc_encrypt(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
    Aes aes;
    int ret;

    ret = wc_AesSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
    if (ret != 0)
        return -1;

    ret = wc_AesCbcEncrypt(&aes, data, data, data_len);
    if (ret != 0)
        return -1;
    return 0;
}


int aes_128_cbc_decrypt(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
    Aes aes;
    int ret;

    ret = wc_AesSetKey(&aes, key, 16, iv, AES_DECRYPTION);
    if (ret != 0)
        return -1;

    ret = wc_AesCbcDecrypt(&aes, data, data, data_len);
    if (ret != 0)
        return -1;
    return 0;
}

#ifndef CONFIG_FIPS
#ifndef CONFIG_OPENSSL_INTERNAL_AES_WRAP
#define AES_KEY_LEN 16
int aes_wrap(const u8 *kek, int n, const u8 *plain, u8 *cipher)
{
    int ret = wc_AesKeyWrap(kek, AES_KEY_LEN, plain, n * 8, cipher, (n + 1) * 8,
                            NULL);
    return ret != (n + 1) * 8 ? -1 : 0;
}

int aes_unwrap(const u8 *kek, int n, const u8 *cipher,
               u8 *plain)
{
    int ret = wc_AesKeyUnWrap(kek, AES_KEY_LEN, cipher, (n + 1) * 8, plain, n * 8,
                              NULL);
    return ret != n * 8 ? -1 : 0;
}
#endif /* CONFIG_OPENSSL_INTERNAL_AES_WRAP */
#endif /* CONFIG_FIPS */

#ifndef CONFIG_NO_RC4
int rc4_skip(const u8 *key, size_t keylen, size_t skip, u8 *data,
             size_t data_len)
{
#ifndef NO_RC4
    Arc4          arc4;
    unsigned char skip_buf[16];

    wc_Arc4SetKey(&arc4, key, keylen);

    while (skip >= sizeof(skip_buf)) {
        size_t len = skip;
        if (len > sizeof(skip_buf))
            len = sizeof(skip_buf);
        wc_Arc4Process(&arc4, skip_buf, skip_buf, len);
        skip -= len;
    }

    wc_Arc4Process(&arc4, data, data, data_len);

    return 0;
#else
    return -1;
#endif
}
#endif /* CONFIG_NO_RC4 */

#ifndef CRYPTO_ABSTRACT_API
#if defined(EAP_WSC) || defined(EAP_IKEV2) || defined(EAP_IKEV2_DYNAMIC) \
                     || defined(EAP_EKE) || defined(EAP_EKE_DYNAMIC) \
                     || defined(CONFIG_SAE)
#ifdef USE_FAST_MATH
int crypto_mod_exp(const u8 *base, size_t base_len,
                   const u8 *power, size_t power_len,
                   const u8 *modulus, size_t modulus_len,
                   u8 *result, size_t *result_len)
{
    mp_int r, a, p, m;
    int ret = -1;

    if (mp_init_multi(&a, &p, &m, &r, NULL, NULL) != 0)
        return ret;

    if ((mp_read_unsigned_bin(&a, base, base_len)) != 0)
        goto done;
    if ((mp_read_unsigned_bin(&p, power, power_len)) != 0)
        goto done;
    if ((mp_read_unsigned_bin(&m, modulus, modulus_len)) != 0)
        goto done;

    if (mp_exptmod(&a, &p, &m, &r) != 0)
        goto done;

    if (mp_to_unsigned_bin(&r, result) != 0)
        goto done;

    *result_len = mp_unsigned_bin_size(&r);
    ret = 0;
done:
    mp_clear(&r);
    mp_clear(&m);
    mp_clear(&p);
    mp_clear(&a);
    return ret;
}
#else
int crypto_mod_exp(const u8 *base, size_t base_len,
                   const u8 *power, size_t power_len,
                   const u8 *modulus, size_t modulus_len,
                   u8 *result, size_t *result_len)
{
    int ret = -1;
    WOLFSSL_BIGNUM *r = NULL, *a = NULL, *p = NULL, *m = NULL;
    int len;

    if ((a = wolfSSL_BN_bin2bn(base, base_len, NULL)) == NULL)
        goto done;
    if ((p = wolfSSL_BN_bin2bn(power, power_len, NULL)) == NULL)
        goto done;
    if ((m = wolfSSL_BN_bin2bn(modulus, modulus_len, NULL)) == NULL)
        goto done;
    if ((r = wolfSSL_BN_new()) == NULL)
        goto done;

    if (wolfSSL_BN_mod_exp(r, a, p, m, NULL) != 1)
        goto done;

    if ((len = wolfSSL_BN_bn2bin(r, result)) < 0)
        goto done;

    *result_len = len;
    ret = 0;
done:
    wolfSSL_BN_free(r);
    wolfSSL_BN_free(m);
    wolfSSL_BN_free(p);
    wolfSSL_BN_free(a);
    return ret;
}
#endif
#endif
#endif

#if defined(EAP_IKEV2) || defined(EAP_IKEV2_DYNAMIC) \
                       || defined(EAP_SERVER_IKEV2)
union wolfssl_cipher
{
    Aes aes;
    Des3 des3;
    Arc4 arc4;
};

struct crypto_cipher {
    enum crypto_cipher_alg alg;
    union wolfssl_cipher enc;
    union wolfssl_cipher dec;
};

struct crypto_cipher* crypto_cipher_init(enum crypto_cipher_alg alg,
                                          const u8 *iv, const u8 *key,
                                          size_t key_len)
{
    struct crypto_cipher *ctx;

    ctx = os_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    switch (alg) {
#ifndef CONFIG_NO_RC4
#ifndef NO_RC4
        case CRYPTO_CIPHER_ALG_RC4:
            wc_Arc4SetKey(&ctx->enc.arc4, key, key_len);
            wc_Arc4SetKey(&ctx->dec.arc4, key, key_len);
            break;
#endif /* NO_RC4 */
#endif /* CONFIG_NO_RC4 */
#ifndef NO_AES
        case CRYPTO_CIPHER_ALG_AES:
            switch (key_len) {
            case 16:
            case 24:
            case 32:
                break;
            default:
                os_free(ctx);
                return NULL;
            }
            if (wc_AesSetKey(&ctx->enc.aes, key, key_len, iv, AES_ENCRYPTION) ||
                wc_AesSetKey(&ctx->dec.aes, key, key_len, iv, AES_DECRYPTION)) {
                os_free(ctx);
                return NULL;
            }
            break;
#endif /* NO_AES */
#ifndef NO_DES3
        case CRYPTO_CIPHER_ALG_3DES:
            if (key_len != DES3_KEYLEN ||
                wc_Des3_SetKey(&ctx->enc.des3, key, iv, DES_ENCRYPTION) ||
                wc_Des3_SetKey(&ctx->dec.des3, key, iv, DES_DECRYPTION)) {
                os_free(ctx);
                return NULL;
            }
            break;
#endif /* NO_DES3 */
        case CRYPTO_CIPHER_ALG_RC2:
        case CRYPTO_CIPHER_ALG_DES:
        default:
            os_free(ctx);
            return NULL;
    }

    ctx->alg = alg;

    return ctx;
}

int crypto_cipher_encrypt(struct crypto_cipher *ctx, const u8 *plain,
                          u8 *crypt, size_t len)
{
    switch (ctx->alg) {
#ifndef CONFIG_NO_RC4
#ifndef NO_RC4
        case CRYPTO_CIPHER_ALG_RC4:
            wc_Arc4Process(&ctx->enc.arc4, crypt, plain, len);
            return 0;
#endif /* NO_RC4 */
#endif /* CONFIG_NO_RC4 */
#ifndef NO_AES
        case CRYPTO_CIPHER_ALG_AES:
            if (wc_AesCbcEncrypt(&ctx->enc.aes, crypt, plain, len) != 0)
                return -1;
            return 0;
#endif /* NO_AES */
#ifndef NO_DES3
        case CRYPTO_CIPHER_ALG_3DES:
            if (wc_Des3_CbcEncrypt(&ctx->enc.des3, crypt, plain, len) != 0)
                return -1;
            return 0;
#endif /* NO_DES3 */
        default:
            return -1;
    }
    return -1;
}


int crypto_cipher_decrypt(struct crypto_cipher *ctx, const u8 *crypt,
                          u8 *plain, size_t len)
{
    switch (ctx->alg) {
#ifndef CONFIG_NO_RC4
#ifndef NO_RC4
        case CRYPTO_CIPHER_ALG_RC4:
            wc_Arc4Process(&ctx->dec.arc4, plain, crypt, len);
            return 0;
#endif /* NO_RC4 */
#endif /* CONFIG_NO_RC4 */
#ifndef NO_AES
        case CRYPTO_CIPHER_ALG_AES:
            if (wc_AesCbcDecrypt(&ctx->dec.aes, plain, crypt, len) != 0)
                return -1;
            return 0;
#endif /* NO_AES */
#ifndef NO_DES3
        case CRYPTO_CIPHER_ALG_3DES:
            if (wc_Des3_CbcDecrypt(&ctx->dec.des3, plain, crypt, len) != 0)
                return -1;
            return 0;
#endif /* NO_DES3 */
        default:
            return -1;
    }
    return -1;
}


void crypto_cipher_deinit(struct crypto_cipher *ctx)
{
    if (ctx != NULL)
        os_free(ctx);
}
#endif

#ifdef CONFIG_WPS
static const unsigned char RFC3526_PRIME_1536[] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
    0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
    0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
    0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
    0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
    0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
    0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
    0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
    0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
    0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
    0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
    0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
    0xCA,0x23,0x73,0x27,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};
static const unsigned char RFC3526_GENERATOR_1536[] = {
    0x02
};

#define RFC3526_LEN       sizeof(RFC3526_PRIME_1536)

void * dh5_init(struct wpabuf **priv, struct wpabuf **publ)
{
    WC_RNG rng;
    DhKey* ret = NULL;
    DhKey* dh = NULL;
    struct wpabuf* privkey = NULL;
    struct wpabuf* pubkey = NULL;
    word32 privSz, pubSz;

    *priv = NULL;
    *publ = NULL;

    dh = os_malloc(sizeof(DhKey));
    if (dh == NULL)
        return NULL;
    wc_InitDhKey(dh);

    if (wc_InitRng(&rng) != 0) {
        os_free(dh);
        return NULL;
    }

    privkey = wpabuf_alloc(RFC3526_LEN);
    pubkey = wpabuf_alloc(RFC3526_LEN);
    if (privkey == NULL || pubkey == NULL)
        goto done;

    if (wc_DhSetKey(dh, RFC3526_PRIME_1536, sizeof(RFC3526_PRIME_1536),
                    RFC3526_GENERATOR_1536, sizeof(RFC3526_GENERATOR_1536))
                    != 0)
        goto done;

    if (wc_DhGenerateKeyPair(dh, &rng, wpabuf_mhead(privkey), &privSz,
                             wpabuf_mhead(pubkey), &pubSz) != 0)
        goto done;

    wpabuf_put(privkey, privSz);
    wpabuf_put(pubkey, pubSz);

    ret = dh;
    *priv = privkey;
    *publ = pubkey;
    dh = NULL;
    privkey = NULL;
    pubkey = NULL;
done:
    wpabuf_free(pubkey);
    wpabuf_free(privkey);
    if (dh != NULL) {
        wc_FreeDhKey(dh);
        os_free(dh);
    }
    wc_FreeRng(&rng);
    return ret;
}

void * dh5_init_fixed(const struct wpabuf *priv, const struct wpabuf *publ)
{
    DhKey* ret = NULL;
    DhKey* dh;
    byte*  secret;
    word32 secretSz;

    dh = os_malloc(sizeof(DhKey));
    if (dh == NULL)
        return NULL;
    wc_InitDhKey(dh);

    secret = os_malloc(RFC3526_LEN);
    if (secret == NULL)
        goto done;

    if (wc_DhSetKey(dh, RFC3526_PRIME_1536, sizeof(RFC3526_PRIME_1536),
                    RFC3526_GENERATOR_1536, sizeof(RFC3526_GENERATOR_1536))
                    != 0)
        goto done;

    if (wc_DhAgree(dh, secret, &secretSz, wpabuf_head(priv), wpabuf_len(priv),
                   RFC3526_GENERATOR_1536, sizeof(RFC3526_GENERATOR_1536)) != 0)
        goto done;

    if (secretSz != wpabuf_len(publ) ||
            os_memcmp(secret, wpabuf_head(publ), secretSz) != 0)
        goto done;

    ret = dh;
    dh = NULL;
done:
    if (dh != NULL) {
        wc_FreeDhKey(dh);
        os_free(dh);
    }
    if (secret != NULL)
        os_free(secret);
    return ret;
}

struct wpabuf * dh5_derive_shared(void *ctx, const struct wpabuf *peer_public,
                                  const struct wpabuf *own_private)
{
    struct wpabuf* ret = NULL;
    struct wpabuf* secret;
    word32         secretSz;

    secret = wpabuf_alloc(RFC3526_LEN);
    if (secret == NULL)
        goto done;

    if (wc_DhAgree(ctx, wpabuf_mhead(secret), &secretSz,
                   wpabuf_head(own_private), wpabuf_len(own_private),
                   wpabuf_head(peer_public), wpabuf_len(peer_public)) != 0)
        goto done;

    wpabuf_put(secret, secretSz);

    ret = secret;
    secret = NULL;
done:
    wpabuf_free(secret);
    return ret;
}

void dh5_free(void *ctx)
{
    if (ctx == NULL)
        return;

    wc_FreeDhKey(ctx);
    os_free(ctx);
}
#endif

#ifdef CRYPTO_ABSTRACT_API
int crypto_dh_init(u8 generator, const u8 *prime, size_t prime_len, u8 *privkey,
                   u8 *pubkey)
{
    int ret = -1;
    WC_RNG rng;
    DhKey* dh = NULL;
    word32 privSz, pubSz;

    dh = os_malloc(sizeof(DhKey));
    if (dh == NULL)
        return -1;
    wc_InitDhKey(dh);

    if (wc_InitRng(&rng) != 0) {
        os_free(dh);
        return -1;
    }

    if (wc_DhSetKey(dh, prime, prime_len, &generator, 1) != 0)
        goto done;

    if (wc_DhGenerateKeyPair(dh, &rng, privkey, &privSz, pubkey, &pubSz) != 0)
        goto done;

    if (privSz < prime_len) {
        size_t padSz = prime_len - privSz;
        os_memmove(privkey + padSz, privkey, privSz);
        os_memset(privkey, 0, padSz);
    }

    if (pubSz < prime_len) {
        size_t padSz = prime_len - pubSz;
        os_memmove(pubkey + padSz, pubkey, pubSz);
        os_memset(pubkey, 0, padSz);
    }
    ret = 0;
done:
    wc_FreeDhKey(dh);
    os_free(dh);
    wc_FreeRng(&rng);
    return ret;
}

int crypto_dh_derive_secret(u8 generator, const u8 *prime, size_t prime_len,
                            const u8 *privkey, size_t privkey_len,
                            const u8 *pubkey, size_t pubkey_len,
                            u8 *secret, size_t *len)
{
    int ret = -1;
    DhKey* dh;
    word32 secretSz;

    dh = os_malloc(sizeof(DhKey));
    if (dh == NULL)
        return -1;
    wc_InitDhKey(dh);

    if (wc_DhSetKey(dh, prime, prime_len, &generator, 1) != 0)
        goto done;

    if (wc_DhAgree(dh, secret, &secretSz, privkey, privkey_len, pubkey,
                   pubkey_len) != 0)
        goto done;

    *len = secretSz;
    ret = 0;
done:
    wc_FreeDhKey(dh);
    os_free(dh);
    return ret;
}
#endif /* CRYPTO_ABSTRACT_API */

#ifdef CONFIG_FIPS
int crypto_get_random(void *buf, size_t len)
{
    int ret = 0;
    WC_RNG rng;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_RNG_GenerateBlock(&rng, buf, len) != 0)
        ret = -1;
    wc_FreeRng(&rng);
    return ret;
}
#endif

#if defined(EAP_PWD) || defined(EAP_SERVER_PWD)
struct crypto_hash {
    Hmac hmac;
    int  size;
};

struct crypto_hash * crypto_hash_init(enum crypto_hash_alg alg, const u8 *key,
                                      size_t key_len)
{
    struct crypto_hash* ret = NULL;
    struct crypto_hash* hash;
    int type;

    hash = os_malloc(sizeof(*hash));
    if (hash == NULL)
        goto done;

    switch (alg) {
#ifndef NO_MD5
        case CRYPTO_HASH_ALG_HMAC_MD5:
            type = MD5;
            hash->size = MD5_DIGEST_SIZE;
            break;
#endif
#ifndef NO_SHA
        case CRYPTO_HASH_ALG_HMAC_SHA1:
            type = SHA;
            hash->size = SHA_DIGEST_SIZE;
            break;
#endif
#ifdef CONFIG_SHA256
#ifndef NO_SHA256
        case CRYPTO_HASH_ALG_HMAC_SHA256:
            type = SHA256;
            hash->size = SHA256_DIGEST_SIZE;
            break;
#endif
#endif
        default:
            goto done;
    }

    if (wc_HmacSetKey(&hash->hmac, type, key, key_len) != 0)
        goto done;

    ret = hash;
    hash = NULL;
done:
    if (hash != NULL)
        os_free(hash);
    return ret;
}
void crypto_hash_update(struct crypto_hash *ctx, const u8 *data, size_t len)
{
     if (ctx == NULL)
         return;
     wc_HmacUpdate(&ctx->hmac, data, len);
}

int crypto_hash_finish(struct crypto_hash *ctx, u8 *mac, size_t *len)
{
     int ret = 0;

     if (ctx == NULL)
         return -2;

     if (mac == NULL || len == NULL)
         goto done;

     if (wc_HmacFinal(&ctx->hmac, mac) != 0) {
         ret = -1;
         goto done;
     }

     *len = ctx->size;
     ret = 0;
done:
     if (ctx != NULL)
         os_free(ctx);
     return ret;
}
#endif

#ifdef CONFIG_WOLFSSL_CMAC
int omac1_aes_vector(const u8 *key, size_t key_len, size_t num_elem,
                     const u8 *addr[], const size_t *len, u8 *mac)
{
    Cmac   cmac;
    int    i;
    word32 sz;

    if (wc_InitCmac(&cmac, key, key_len, WC_CMAC_AES, NULL) != 0)
        return -1;

    for (i = 0; i < num_elem; i++)
        if (wc_CmacUpdate(&cmac, addr[i], len[i]) != 0)
            return -1;

    sz = AES_BLOCK_SIZE;
    if (wc_CmacFinal(&cmac, mac, &sz) != 0 || sz != AES_BLOCK_SIZE)
        return -1;

    return 0;
}


int omac1_aes_128_vector(const u8 *key, size_t num_elem,
                         const u8 *addr[], const size_t *len, u8 *mac)
{
    return omac1_aes_vector(key, 16, num_elem, addr, len, mac);
}


int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
    return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}


int omac1_aes_256(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
    return omac1_aes_vector(key, 32, 1, &data, &data_len, mac);
}
#endif


struct crypto_bignum* crypto_bignum_init(void)
{
    mp_int* a;

    a = os_malloc(sizeof(*a));
    if (mp_init(a) != MP_OKAY) {
        os_free(a);
        a = NULL;
    }

    return (struct crypto_bignum*)a;
}


struct crypto_bignum * crypto_bignum_init_set(const u8 *buf, size_t len)
{
    mp_int* a;

    a = (mp_int*)crypto_bignum_init();
    if (a == NULL)
        return NULL;

    if (mp_read_unsigned_bin(a, buf, len) != MP_OKAY) {
        os_free(a);
        a = NULL;
    }

    return (struct crypto_bignum*)a;
}


void crypto_bignum_deinit(struct crypto_bignum *n, int clear)
{
    if (n == NULL)
        return;

    if (clear)
        mp_forcezero((mp_int*)n);
    mp_clear((mp_int*)n);
    os_free((mp_int*)n);
}


int crypto_bignum_to_bin(const struct crypto_bignum *a,
                         u8 *buf, size_t buflen, size_t padlen)
{
    int num_bytes, offset;

    if (padlen > buflen)
        return -1;

    num_bytes = (mp_count_bits((mp_int*)a) + 7) / 8;
    if ((size_t)num_bytes > buflen)
        return -1;
    if (padlen > (size_t)num_bytes)
        offset = padlen - num_bytes;
    else
        offset = 0;

    os_memset(buf, 0, offset);
    mp_to_unsigned_bin((mp_int*)a, buf + offset);

    return num_bytes + offset;
}

int crypto_bignum_rand(struct crypto_bignum *r, const struct crypto_bignum *m)
{
    int ret = 0;
    WC_RNG rng;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (mp_rand_prime((mp_int*)r, (mp_count_bits((mp_int*)m) + 7) / 8 * 2, &rng,
                      NULL) != 0) {
        ret = -1;
    }
    if (ret == 0 && mp_mod((mp_int*)r, (mp_int*)m, (mp_int*)r) != 0)
        ret = -1;
    wc_FreeRng(&rng);
    return ret;
}

int crypto_bignum_add(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *r)
{
    return mp_add((mp_int*)a, (mp_int*)b, (mp_int*)r) == MP_OKAY ? 0 : -1;
}


int crypto_bignum_mod(const struct crypto_bignum *a,
                      const struct crypto_bignum *m,
                      struct crypto_bignum *r)
{
    return mp_mod((mp_int*)a, (mp_int*)m, (mp_int*)r) == MP_OKAY ? 0 : -1;
}


int crypto_bignum_exptmod(const struct crypto_bignum *b,
                          const struct crypto_bignum *e,
                          const struct crypto_bignum *m,
                          struct crypto_bignum *r)
{
    int res;

    res = mp_exptmod((mp_int*)b, (mp_int*)e, (mp_int*)m, (mp_int*)r);
    return res == MP_OKAY ?  0 : -1;
}


int crypto_bignum_inverse(const struct crypto_bignum *a,
                          const struct crypto_bignum *m,
                          struct crypto_bignum *r)
{
    return mp_invmod((mp_int*)a, (mp_int*)m, (mp_int*)r) == MP_OKAY ? 0 : -1;
}


int crypto_bignum_sub(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *r)
{
    return mp_add((mp_int*)a, (mp_int*)b, (mp_int*)r) == MP_OKAY ? 0 : -1;
}


int crypto_bignum_div(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *d)
{
    return mp_div((mp_int*)a, (mp_int*)b, (mp_int*)d, NULL) == MP_OKAY ? 0 : -1;
}


int crypto_bignum_mulmod(const struct crypto_bignum *a,
                         const struct crypto_bignum *b,
                         const struct crypto_bignum *m,
                         struct crypto_bignum *d)
{
    int res;

    res = mp_mulmod((mp_int*)a, (mp_int*)b, (mp_int*)m, (mp_int*)d);
    return res == MP_OKAY ?  0 : -1;
}

int crypto_bugnum_rshift(const struct crypto_bignum *a, int n,
			 struct crypto_bignum *r)
{
    if (mp_copy((mp_int*)a, (mp_int*)r) != MP_OKAY)
        return -1;
    mp_rshd((mp_int*)r, n);
    return 0;
}

int crypto_bignum_cmp(const struct crypto_bignum *a,
                      const struct crypto_bignum *b)
{
    return mp_cmp((mp_int*)a, (mp_int*)b);
}


int crypto_bignum_bits(const struct crypto_bignum *a)
{
    return mp_count_bits((mp_int*)a);
}


int crypto_bignum_is_zero(const struct crypto_bignum *a)
{
    return mp_iszero((mp_int*)a);
}


int crypto_bignum_is_one(const struct crypto_bignum *a)
{
    return mp_isone((mp_int*)a);
}

int crypto_bignum_is_odd(const struct crypto_bignum *a)
{
    return mp_isodd((mp_int*)a);
}


int crypto_bignum_legendre(const struct crypto_bignum *a,
                           const struct crypto_bignum *p)
{
    mp_int t;
    int ret;
    int res = -2;

    if (mp_init(&t) != MP_OKAY) {
        return -2;
    }

    /* t = (p-1) / 2 */
    ret = mp_sub_d((mp_int*)p, 1, &t);
    if (ret == MP_OKAY)
        mp_rshb(&t, 1);
    if (ret == MP_OKAY)
        ret = mp_exptmod((mp_int*)a, &t, (mp_int*)p, &t);
    if (ret == MP_OKAY) {
        if (mp_isone(&t))
            res = 1;
        else if (mp_iszero(&t))
            res = 0;
        else
            res = -1;
    }

    mp_clear(&t);
    return res;
}


#ifdef CONFIG_ECC
extern int ecc_map(ecc_point*, mp_int*, mp_digit);
extern int ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R,
                                    mp_int* a, mp_int* modulus, mp_digit mp);

struct crypto_ec {
    ecc_key  key;
    mp_int   a;
    mp_int   prime;
    mp_int   order;
    mp_digit montB;
    mp_int   b;
};

struct crypto_ec * crypto_ec_init(int group)
{
    int built = 0;
    struct crypto_ec *e;
    int curve_id;

    /* Map from IANA registry for IKE D-H groups to OpenSSL NID */
    switch (group) {
        case 19:
            curve_id = ECC_SECP256R1;
            break;
        case 20:
            curve_id = ECC_SECP384R1;
            break;
        case 21:
            curve_id = ECC_SECP521R1;
            break;
        case 25:
            curve_id = ECC_SECP192R1;
            break;
        case 26:
            curve_id = ECC_SECP224R1;
            break;
#ifdef HAVE_ECC_BRAINPOOL
        case 27:
            curve_id = ECC_BRAINPOOLP224R1;
            break;
        case 28:
            curve_id = ECC_BRAINPOOLP256R1;
            break;
        case 29:
            curve_id = ECC_BRAINPOOLP384R1;
            break;
        case 30:
            curve_id = ECC_BRAINPOOLP512R1;
            break;
#endif /* HAVE_ECC_BRAINPOOL */
        default:
            return NULL;
    }

    e = os_zalloc(sizeof(*e));
    if (e == NULL)
        return NULL;

    if (wc_ecc_init(&e->key) != 0)
        goto done;
    if (wc_ecc_set_curve(&e->key, 0, curve_id) != 0)
        goto done;

    if (mp_init(&e->a) != MP_OKAY)
        goto done;
    if (mp_init(&e->prime) != MP_OKAY)
        goto done;
    if (mp_init(&e->order) != MP_OKAY)
        goto done;
    if (mp_init(&e->b) != MP_OKAY)
        goto done;

    if (mp_read_radix(&e->a, e->key.dp->Af, 16) != MP_OKAY)
        goto done;
    if (mp_read_radix(&e->b, e->key.dp->Bf, 16) != MP_OKAY)
        goto done;
    if (mp_read_radix(&e->prime, e->key.dp->prime, 16) != MP_OKAY)
        goto done;
    if (mp_read_radix(&e->order, e->key.dp->order, 16) != MP_OKAY)
        goto done;

    if (mp_montgomery_setup(&e->prime, &e->montB) != MP_OKAY)
        goto done;

    built = 1;
done:
    if (!built) {
        crypto_ec_deinit(e);
        e = NULL;
    }
    return e;
}


void crypto_ec_deinit(struct crypto_ec* e)
{
    if (e == NULL)
        return;

    mp_clear(&e->b);
    mp_clear(&e->order);
    mp_clear(&e->prime);
    mp_clear(&e->a);
    wc_ecc_free(&e->key);
    os_free(e);
}

int crypto_ec_cofactor(struct crypto_ec* e, struct crypto_bignum* cofactor)
{
    if (e == NULL || cofactor == NULL)
        return -1;

    mp_set((mp_int*)cofactor, e->key.dp->cofactor);
    return 0;
}

struct crypto_ec_point* crypto_ec_point_init(struct crypto_ec* e)
{
    if (e == NULL)
        return NULL;
    return (struct crypto_ec_point*)wc_ecc_new_point();
}


size_t crypto_ec_prime_len(struct crypto_ec *e)
{
    return (mp_count_bits(&e->prime) + 7) / 8;
}


size_t crypto_ec_prime_len_bits(struct crypto_ec *e)
{
    return mp_count_bits(&e->prime);
}


size_t crypto_ec_order_len(struct crypto_ec *e)
{
    return (mp_count_bits(&e->order) + 7) / 8;
}


const struct crypto_bignum * crypto_ec_get_prime(struct crypto_ec *e)
{
    return (const struct crypto_bignum *)&e->prime;
}


const struct crypto_bignum * crypto_ec_get_order(struct crypto_ec *e)
{
    return (const struct crypto_bignum *)&e->order;
}


void crypto_ec_point_deinit(struct crypto_ec_point *p, int clear)
{
    ecc_point* point = (ecc_point*)p;

    if (p == NULL)
        return;

    if (clear) {
        mp_forcezero(point->x);
        mp_forcezero(point->y);
        mp_forcezero(point->z);
    }
    wc_ecc_del_point(point);
}

int crypto_ec_point_x(const struct crypto_ec_point *p, struct crypto_bignum *x)
{
    return mp_copy(((ecc_point*)p)->x, (mp_int*)x) == MP_OKAY ? 0 : -1;
}

int crypto_ec_point_to_bin(struct crypto_ec *e,
                           const struct crypto_ec_point *point, u8 *x, u8 *y)
{
    ecc_point* p = (ecc_point*)point;

    if (!mp_isone(p->z)) {
        if (ecc_map(p, &e->prime, e->montB) != MP_OKAY)
            return -1;
    }

    if (x != NULL) {
        if (crypto_bignum_to_bin((struct crypto_bignum *)p->x, x,
                                 e->key.dp->size, e->key.dp->size) <= 0) {
            return -1;
        }
    }
    if (y != NULL) {
        if (crypto_bignum_to_bin((struct crypto_bignum *)p->y, y,
                                 e->key.dp->size, e->key.dp->size) <= 0) {
            return -1;
        }
    }

    return 0;
}


struct crypto_ec_point* crypto_ec_point_from_bin(struct crypto_ec *e,
                                                 const u8 *val)
{
    ecc_point* point = NULL;
    int loaded = 0;

    point = wc_ecc_new_point();
    if (point == NULL)
        goto done;

    if (mp_read_unsigned_bin(point->x, val, e->key.dp->size) != MP_OKAY)
        goto done;
    val += e->key.dp->size;
    if (mp_read_unsigned_bin(point->y, val, e->key.dp->size) != MP_OKAY)
        goto done;
    mp_set(point->z, 1);

    loaded = 1;
done:
    if (!loaded) {
        wc_ecc_del_point(point);
        point = NULL;
    }
    return (struct crypto_ec_point*)point;
}


int crypto_ec_point_add(struct crypto_ec *e, const struct crypto_ec_point *a,
                        const struct crypto_ec_point *b,
                        struct crypto_ec_point *c)
{
    mp_int mu;
    ecc_point *ta = NULL, *tb = NULL;
    ecc_point *pa = (ecc_point*)a, *pb = (ecc_point*)b;
    mp_int *modulus = &e->prime;
    int ret;

    if ((ret = mp_init(&mu)) != MP_OKAY) {
        return -1;
    }
    if ((ret = mp_montgomery_calc_normalization(&mu, modulus)) != MP_OKAY) {
        mp_clear(&mu);
        return -1;
    }

    if (!mp_isone(&mu)) {
        ta = wc_ecc_new_point();
        if (ta == NULL) {
            mp_clear(&mu);
            return -1;
        }
        tb = wc_ecc_new_point();
        if (tb == NULL) {
            wc_ecc_del_point(ta);
            mp_clear(&mu);
            return -1;
        }

        if (mp_mulmod(pa->x, &mu, modulus, ta->x) != MP_OKAY) {
            ret = -1;
            goto end;
        }
        if (mp_mulmod(pa->y, &mu, modulus, ta->y) != MP_OKAY) {
            ret = -1;
            goto end;
        }
        if (mp_mulmod(pa->z, &mu, modulus, ta->z) != MP_OKAY) {
            ret = -1;
            goto end;
        }
        if (mp_mulmod(pb->x, &mu, modulus, tb->x) != MP_OKAY) {
            ret = -1;
            goto end;
        }
        if (mp_mulmod(pb->y, &mu, modulus, tb->y) != MP_OKAY) {
            ret = -1;
            goto end;
        }
        if (mp_mulmod(pb->z, &mu, modulus, tb->z) != MP_OKAY) {
            ret = -1;
            goto end;
        }
        pa = ta;
        pb = tb;
    }

    ret = ecc_projective_add_point(pa, pb, (ecc_point*)c, &e->a, &e->prime,
                                   e->montB);
    if (ret != 0) {
        ret = -1;
        goto end;
    }

    if (ecc_map((ecc_point*)c, &e->prime, e->montB) != MP_OKAY)
        ret = -1;
    else
        ret = 0;
end:
    wc_ecc_del_point(tb);
    wc_ecc_del_point(ta);
    mp_clear(&mu);
    return ret;
}


int crypto_ec_point_mul(struct crypto_ec *e, const struct crypto_ec_point *p,
                        const struct crypto_bignum *b,
                        struct crypto_ec_point *res)
{
    int ret;

    ret = wc_ecc_mulmod((mp_int*)b, (ecc_point*)p, (ecc_point*)res, &e->a,
                        &e->prime, 1);
    return ret == 0 ? 0 : -1;
}


int crypto_ec_point_invert(struct crypto_ec *e, struct crypto_ec_point *p)
{
    ecc_point* point = (ecc_point*)p;

    if (mp_sub(&e->prime, point->y, point->y) != MP_OKAY)
        return -1;

    return 0;
}


int crypto_ec_point_solve_y_coord(struct crypto_ec *e,
                                  struct crypto_ec_point *p,
                                  const struct crypto_bignum *x, int y_bit)
{
    byte buf[MAX_ECC_BYTES + 1];
    int ret;
    int prime_len = crypto_ec_prime_len(e);

    buf[0] = 0x2 + (byte)y_bit;
    ret = crypto_bignum_to_bin(x, buf + 1, prime_len, prime_len);
    if (ret <= 0)
        return -1;
    ret = wc_ecc_import_point_der(buf, ret + 1, e->key.idx, (ecc_point*)p);
    if (ret != 0)
        return -1;

    return 0;
}


struct crypto_bignum *
crypto_ec_point_compute_y_sqr(struct crypto_ec *e,
                              const struct crypto_bignum *x)
{
    mp_int* y2 = NULL;
    mp_int t;
    int calced = 0;

    if (mp_init(&t) != MP_OKAY)
        return NULL;

    y2 = (mp_int*)crypto_bignum_init();
    if (y2 == NULL)
        goto done;

    if (mp_sqrmod((mp_int*)x, &e->prime, y2) != 0)
        goto done;
    if (mp_mulmod((mp_int*)x, &t, &e->prime, y2) != 0)
        goto done;
    if (mp_mulmod((mp_int*)x, &e->a, &e->prime, &t) != 0)
        goto done;
    if (mp_addmod(y2, &t, &e->prime, y2) != 0)
        goto done;
    if (mp_addmod(y2, &e->b, &e->prime, y2) != 0)
        goto done;

    calced = 1;
done:
    if (!calced) {
        if (y2 != NULL) {
            mp_clear(y2);
            os_free(y2);
        }
        mp_clear(&t);
    }

    return (struct crypto_bignum*)y2;
}


int crypto_ec_point_is_at_infinity(struct crypto_ec *e,
                                   const struct crypto_ec_point *p)
{
    return wc_ecc_point_is_at_infinity((ecc_point*)p);
}


int crypto_ec_point_is_on_curve(struct crypto_ec *e,
                                const struct crypto_ec_point *p)
{
    return wc_ecc_is_point((ecc_point*)p, &e->a, &e->b, &e->prime) == MP_OKAY;
}


int crypto_ec_point_cmp(const struct crypto_ec *e,
                        const struct crypto_ec_point *a,
                        const struct crypto_ec_point *b)
{
    return wc_ecc_cmp_point((ecc_point*)a, (ecc_point*)b);
}

#endif /* CONFIG_ECC */
