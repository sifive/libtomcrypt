/*
 * Copyright (c) mogoweb (mogoweb@gmail.com). All rights reserved.
 * Copyright (c) 2015 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Implements SM2 encrypt/decrypt according to chinese standard GM/T 0003.4-2012
 *
 * ECC curve parameters refer to chinese standard GM/T 0003.5-2012
 */

#include "tomcrypt_private.h"

#ifdef LTC_SM2

int sm2_encrypt(const unsigned char *in, size_t inlen,
                unsigned char *out, size_t *outlen, ecc_key *key)
{
    return sm2_encrypt_ex(in, inlen, out, outlen, key, NULL);
}

int sm2_encrypt_ex(const unsigned char *in, size_t inlen,
                unsigned char *out, size_t *outlen, ecc_key *key, const char *ik)
{
    int           err, inf;
    prng_state    yarrow_prng;
    int           wprng, hash_idx;
    const struct ltc_hash_descriptor *hash_desc;
    hash_state    md;
    unsigned char hash_buf[HASH_MAX_MD_SIZE];
    ecc_point     *mG = NULL, *mQ = NULL, *mS = NULL;
    void          *mu = NULL, *ma = NULL;
    void          *mp = NULL;
    void          *k, *n, *p, *a, *a_plus3, *h;
    unsigned char *buf = NULL, *outbuf = NULL;
    size_t        len, i;
    int           all_zero;

    wprng = find_prng("yarrow");
    if ((err = rng_make_prng(128, wprng, &yarrow_prng, NULL)) != CRYPT_OK) {
        return CRYPT_INVALID_PRNG;
    }

    hash_idx = find_hash("sm3");
    if (hash_idx < 0) {
        return CRYPT_INVALID_HASH;
    }
    hash_desc = &hash_descriptor[hash_idx];

    if ((err = mp_init_multi(&k, &n, &p, &a, &a_plus3, &h, NULL)) != CRYPT_OK) {
        return err;
    }

    n = key->dp.order;
    p = key->dp.prime;
    a = key->dp.A;
    if ((err = mp_add_d(a, 3, a_plus3)) != CRYPT_OK) {
        goto error;
    }

    /* allocate points */
    mG = ltc_ecc_new_point();
    mQ = ltc_ecc_new_point();
    mS = ltc_ecc_new_point();
    if (mQ  == NULL || mG == NULL || mS == NULL) {
        err = CRYPT_MEM;
        goto error;
    }

    /* find mG and mQ */
    if ((err = ltc_ecc_copy_point(&key->dp.base, mG)) != CRYPT_OK)                                  { goto error; }
    if ((err = ltc_ecc_copy_point(&key->pubkey, mQ)) != CRYPT_OK)                                   { goto error; }

    /* find the montgomery mp */
    if ((err = mp_montgomery_setup(p, &mp)) != CRYPT_OK)                                            { goto error; }

    /* for curves with a == -3 keep ma == NULL */
    if (mp_cmp(a_plus3, p) != LTC_MP_EQ) {
        if ((err = mp_init_multi(&mu, &ma, NULL)) != CRYPT_OK)                                      { goto error; }
        if ((err = mp_montgomery_normalization(mu, p)) != CRYPT_OK)                                 { goto error; }
        if ((err = mp_mulmod(a, mu, p, ma)) != CRYPT_OK)                                            { goto error; }
    }

    do {
        /* get random k and compute [k]G */
        if (!ik) {
            if ((err = rand_bn_upto(k, key->dp.order, &yarrow_prng, wprng)) != CRYPT_OK)            { goto error; }
        } else {
            if ((err = mp_read_radix(k, ik, 16)) != CRYPT_OK)                                       { goto error; }
        }
        if ((err = ltc_mp.ecc_ptmul(k, mG, mG, a, p, 0)) != CRYPT_OK)                               { goto error; }
        /* C1 = mG */
        if ((err = ltc_mp.ecc_map(mG, p, mp)) != CRYPT_OK)                                          { goto error; }

        /* check S = [h] * PB is a inifinity point */
        /* h is ecc curve parameter cofactor */
        if ((err = mp_set_int(h, key->dp.cofactor)) != CRYPT_OK)                                    { goto error; }
        if ((err = ltc_mp.ecc_ptmul(h, mQ, mS, a, p, 0)) != CRYPT_OK)                { goto error; }
        err = ltc_ecc_is_point_at_infinity(mS, p, &inf);
        if (err != CRYPT_OK || inf) {
            err = CRYPT_ERROR;
            goto error;
        }

        /* compute [k] * PB -> (x2, y2) */
        if ((err = ltc_mp.ecc_ptmul(k, mQ, mQ, a, p, 0)) != CRYPT_OK)                               { goto error; }
        if ((err = ltc_mp.ecc_map(mQ, p, mp)) != CRYPT_OK)                                          { goto error; }
    
        /* t = KDF(x2 || y2, klen) */
        len = mp_unsigned_bin_size(mQ->x);
        buf = XMALLOC(len * 2);
        outbuf = XMALLOC(inlen);
        if ((err = mp_to_unsigned_bin(mQ->x, buf)) != CRYPT_OK)                                     { goto error; }
        if ((err = mp_to_unsigned_bin(mQ->y, buf + len)) != CRYPT_OK)                               { goto error; }
#ifdef LTC_TEST_SM2
        printf("(x2, y2)=");
        for (i = 0; i < len * 2; i++) {
            printf("%02X", buf[i]);
        }
        printf("\n");
#endif
        if ((err = x963_kdf(hash_idx, buf, len * 2, outbuf, inlen)) != CRYPT_OK)                    { goto error; }
#ifdef LTC_TEST_SM2
        printf("t=");
        for (i = 0; i < inlen; i++) {
            printf("%02X", outbuf[i]);
        }
        printf("\n");
#endif

        /* check if t all zero */
        all_zero = 1;
        for (i = 0; i < inlen; i++) {
            if ((unsigned char)outbuf[i] != 0) {
                all_zero = 0;
                break;
            }
        }

        if (!all_zero) {
            break;
        }

        XFREE(buf);
        XFREE(outbuf);
        buf = NULL;
        outbuf = NULL;
    } while (1);
    
    /* C2 = M xor t */
    for (i = 0; i < inlen; i++) {
        outbuf[i] ^= in[i];
    }

    /* C3= H256(x2 || M || y2) */
    if ( hash_desc->init(&md)
            || hash_desc->process(&md, buf, len)
            || hash_desc->process(&md, in, inlen)
            || hash_desc->process(&md, buf + len, len)
            || hash_desc->done(&md, hash_buf)) {
        err = CRYPT_INVALID_HASH;
        goto error;
    }
    
    /* return C1 || C3 || C2 */
    if (*outlen < len + hash_desc->hashsize + inlen) {
        err = CRYPT_OVERFLOW;
    }

    *outlen = 1 + len * 2 + hash_desc->hashsize + inlen;
    out[0] = 04;
    if ((err = mp_to_unsigned_bin(mG->x, out + 1)) != CRYPT_OK)                                 { goto error; }
    if ((err = mp_to_unsigned_bin(mG->y, out + 1 + len)) != CRYPT_OK)                           { goto error; }
    XMEMCPY(out + 1 + len * 2, hash_buf, hash_desc->hashsize);
    XMEMCPY(out + 1 + len * 2 + hash_desc->hashsize, outbuf, inlen);

    err = CRYPT_OK;
error:
    if (mG != NULL) ltc_ecc_del_point(mG);
    if (mQ != NULL) ltc_ecc_del_point(mQ);
    if (mS != NULL) ltc_ecc_del_point(mS);
    if (mu != NULL) mp_clear(mu);
    if (ma != NULL) mp_clear(ma);
    mp_clear_multi(k, n, p, a, a_plus3, h, NULL);
    if (mp != NULL) mp_montgomery_free(mp);
    if (buf != NULL) XFREE(buf);
    if (outbuf != NULL) XFREE(outbuf);

    return err;
}

int sm2_decrypt(const unsigned char *in, size_t inlen,
                unsigned char *out, size_t *outlen, ecc_key *key)
{
    int           err, inf;
    prng_state    yarrow_prng;
    int           wprng, hash_idx;
    const struct ltc_hash_descriptor *hash_desc;
    hash_state    md;
    unsigned char hash_buf[HASH_MAX_MD_SIZE];
    ecc_point     *mG = NULL, *mQ = NULL, *mS = NULL;
    void          *mu = NULL, *ma = NULL;
    void          *mp = NULL;
    void          *x, *y, *n, *p, *a, *a_plus3, *h;
    unsigned char *buf = NULL, *outbuf = NULL;
    size_t        len, i;
    int           all_zero;

    wprng = find_prng("yarrow");
    if ((err = rng_make_prng(128, wprng, &yarrow_prng, NULL)) != CRYPT_OK) {
        return CRYPT_INVALID_PRNG;
    }

    hash_idx = find_hash("sm3");
    if (hash_idx < 0) {
        return CRYPT_INVALID_HASH;
    }
    hash_desc = &hash_descriptor[hash_idx];

    if ((err = mp_init_multi(&x, &y, &n, &p, &a, &a_plus3, &h, NULL)) != CRYPT_OK) {
        return err;
    }

    n = key->dp.order;
    p = key->dp.prime;
    a = key->dp.A;
    if ((err = mp_add_d(a, 3, a_plus3)) != CRYPT_OK) {
        goto error;
    }

    /* allocate points */
    mG = ltc_ecc_new_point();
    mQ = ltc_ecc_new_point();
    mS = ltc_ecc_new_point();
    if (mQ  == NULL || mG == NULL || mS == NULL) {
        err = CRYPT_MEM;
        goto error;
    }

    /* find mG */
    if ((err = ltc_ecc_copy_point(&key->dp.base, mG)) != CRYPT_OK)                                  { goto error; }

    /* find the montgomery mp */
    if ((err = mp_montgomery_setup(p, &mp)) != CRYPT_OK)                                            { goto error; }

    /* for curves with a == -3 keep ma == NULL */
    if (mp_cmp(a_plus3, p) != LTC_MP_EQ) {
        if ((err = mp_init_multi(&mu, &ma, NULL)) != CRYPT_OK)                                      { goto error; }
        if ((err = mp_montgomery_normalization(mu, p)) != CRYPT_OK)                                 { goto error; }
        if ((err = mp_mulmod(a, mu, p, ma)) != CRYPT_OK)                                            { goto error; }
    }

    /* restore C1 to point (x, y), check if valid */
    len = key->dp.size;
    if (in[0] != 04)  /* only support uncompressed point */                                         { err = CRYPT_ERROR; goto error; }
    if ((err = mp_read_unsigned_bin(x, (unsigned char*)in + 1, len)) != CRYPT_OK)                   { goto error; }
    if ((err = mp_read_unsigned_bin(y, (unsigned char*)in + 1 + len, len)) != CRYPT_OK)             { goto error; }
    if ((err = ltc_ecc_is_point(&key->dp, x, y)) != CRYPT_OK)                                       { goto error; }

    /* check S = [h] * C1 is a infinity point */
    /* h is ecc curve parameter cofactor */
    if ((err = mp_set_int(h, key->dp.cofactor)) != CRYPT_OK)                                        { goto error; }
    if ((err = mp_copy(x, mQ->x)) != CRYPT_OK)                                                      { goto error; }
    if ((err = mp_copy(y, mQ->y)) != CRYPT_OK)                                                      { goto error; }
    if ((err = mp_set(mQ->z, 1)) != CRYPT_OK)                                                       { goto error; }
    if ((err = ltc_mp.ecc_ptmul(h, mQ, mS, a, p, 0)) != CRYPT_OK)                                   { goto error; }
    err = ltc_ecc_is_point_at_infinity(mS, p, &inf);
    if (err != CRYPT_OK || inf) {
        err = CRYPT_ERROR;
        goto error;
    }

    /* compute (x2, y2) = [dB] * C1 */
    if ((err = ltc_mp.ecc_ptmul(key->k, mQ, mQ, a, p, 0)) != CRYPT_OK)                              { goto error; }
    if ((err = ltc_mp.ecc_map(mQ, p, mp)) != CRYPT_OK)                                              { goto error; }

    /* t = KDF(x2 || y2, klen) */
    buf = XMALLOC(len * 2);
    if ((err = mp_to_unsigned_bin(mQ->x, buf)) != CRYPT_OK)                                     { goto error; }
    if ((err = mp_to_unsigned_bin(mQ->y, buf+ len)) != CRYPT_OK)                               { goto error; }
#ifdef LTC_TEST_SM2
    printf("(x2, y2)=");
    for (i = 0; i < len * 2; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
#endif

    *outlen = inlen - 1 - len * 2 - hash_desc->hashsize;
    outbuf = XMALLOC(*outlen);
    if ((err = x963_kdf(hash_idx, buf, len * 2, outbuf, *outlen)) != CRYPT_OK)                    { goto error; }
#ifdef LTC_TEST_SM2
    printf("t=");
    for (i = 0; i < *outlen; i++) {
        printf("%02X", outbuf[i]);
    }
    printf("\n");
#endif

    /* check if t all zero */
    all_zero = 1;
    for (i = 0; i < *outlen; i++) {
        if ((unsigned char)outbuf[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    if (all_zero) {
        err = CRYPT_ERROR;
        goto error;
    }

    /* M' = C2 xor t */
    for (i = 0; i < *outlen; i++) {
        out[i] = in[inlen - *outlen + i] ^ outbuf[i];
    }

    /* u = H256(x2 || M' || y2) */
    if ( hash_desc->init(&md)
            || hash_desc->process(&md, buf, len)
            || hash_desc->process(&md, out, *outlen)
            || hash_desc->process(&md, buf + len, len)
            || hash_desc->done(&md, hash_buf)) {
        err = CRYPT_INVALID_HASH;
        goto error;
    }

    /* compare u and C3 */
    if (XMEMCMP(hash_buf, in + 1 + len * 2, hash_desc->hashsize)) {
        err = CRYPT_ERROR;
        goto error;
    }

    err = CRYPT_OK;
error:
    if (mG != NULL) ltc_ecc_del_point(mG);
    if (mQ != NULL) ltc_ecc_del_point(mQ);
    if (mS != NULL) ltc_ecc_del_point(mS);
    if (mu != NULL) mp_clear(mu);
    if (ma != NULL) mp_clear(ma);
    mp_clear_multi(x, y, n, p, a, a_plus3, h, NULL);
    if (mp != NULL) mp_montgomery_free(mp);
    if (buf != NULL) XFREE(buf);
    if (outbuf != NULL) XFREE(outbuf);

    return err;
}

#endif  /* LTC_SM2 */
