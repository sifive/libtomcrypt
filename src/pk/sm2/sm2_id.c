/* ====================================================================
 * Copyright (c) 2021 mogoweb(mogoweb@gmail.com). All rights reserved.
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 */
#include "tomcrypt_private.h"

#include "sm2_lcl.h"

#ifdef LTC_SM2

/**
 * packet ECC public key data. output as a||b||xG||yG||xA||yA
 */ 
int sm2_get_public_key_data(const ecc_key *ec_key, unsigned char *out, size_t *outlen)
{
    int err = CRYPT_OK;
    unsigned char buf[ECC_BUF_SIZE];
    int xsize;
    unsigned char *pout;

    int nbytes;
    size_t len;

    if (!ec_key || !out || !outlen) {
        return CRYPT_INVALID_ARG;
    }

    /* degree is the bit length of field element, not the order of subgroup */
    nbytes = ec_key->dp.size;
    len = nbytes * 6;

    if (*outlen < len) {
        return CRYPT_BUFFER_OVERFLOW;
    }

    memset(out, 0, len);
    pout = out;

    xsize = mp_unsigned_bin_size(ec_key->dp.A);
    assert(xsize == nbytes);
    zeromem(buf, sizeof(buf));
    if ((err = mp_to_unsigned_bin(ec_key->dp.A, buf) != CRYPT_OK)) return err;
    XMEMCPY(pout, buf, nbytes);
    pout += nbytes;

    xsize = mp_unsigned_bin_size(ec_key->dp.B);
    assert(xsize == nbytes);
    zeromem(buf, sizeof(buf));
    if ((err = mp_to_unsigned_bin(ec_key->dp.B, buf) != CRYPT_OK)) return err;
    XMEMCPY(pout, buf, nbytes);
    pout += nbytes;

    xsize = mp_unsigned_bin_size(ec_key->dp.base.x);
    assert(xsize == nbytes);
    zeromem(buf, sizeof(buf));
    if ((err = mp_to_unsigned_bin(ec_key->dp.base.x, buf) != CRYPT_OK)) return err;
    XMEMCPY(pout, buf, nbytes);
    pout += nbytes;

    xsize = mp_unsigned_bin_size(ec_key->dp.base.y);
    assert(xsize == nbytes);
    zeromem(buf, sizeof(buf));
    if ((err = mp_to_unsigned_bin(ec_key->dp.base.y, buf) != CRYPT_OK)) return err;
    XMEMCPY(pout, buf, nbytes);
    pout += nbytes;

    xsize = mp_unsigned_bin_size(ec_key->pubkey.x);
    assert(xsize == nbytes);
    zeromem(buf, sizeof(buf));
    if ((err = mp_to_unsigned_bin(ec_key->pubkey.x, buf) != CRYPT_OK)) return err;
    XMEMCPY(pout, buf, nbytes);
    pout += nbytes;

    xsize = mp_unsigned_bin_size(ec_key->pubkey.y);
    assert(xsize == nbytes);
    zeromem(buf, sizeof(buf));
    if ((err = mp_to_unsigned_bin(ec_key->pubkey.y, buf) != CRYPT_OK)) return err;
    XMEMCPY(pout, buf, nbytes);

    *outlen = len;

    return CRYPT_OK;
}

/**
 * Compute ZA. 
 * According to GM/T 0003.2-2012, ZA=H256(ENTLA||IDA||a||b||xG||yG||xA||yA)
 * @param hash_desc The hash function to use
 * @param id        The user identity
 * @param inlen     The length of the id
 * @param out       [out] The destination for the signature
 * @param outlen    [in/out] The max size and resulting size of the signature
 * @param key       A private ECC key
 * @return CRYPT_OK if successful
 */
int sm2_compute_id_digest(const struct ltc_hash_descriptor *hash_desc, const char *id, unsigned long idlen,
        unsigned char *out, unsigned long *outlen, const ecc_key *ec_key)
{
    int ret = CRYPT_OK;
    unsigned char idbits[2];
    unsigned char pkdata[SM2_MAX_PKEY_DATA_LENGTH];
    unsigned int len;
    size_t size;
    hash_state hash_st;

    if (!hash_desc || !id || idlen <= 0 || !out || !outlen || !ec_key) {
        return CRYPT_INVALID_ARG;
    }

    if (idlen > SM2_MAX_ID_LENGTH || idlen <= 0) {
        return CRYPT_INVALID_ARG;
    }

    if (*outlen < hash_desc->hashsize) {
        return CRYPT_INVALID_ARG;
    }

    /* get public key data from ec_key */
    size = sizeof(pkdata);
    if ((ret = sm2_get_public_key_data(ec_key, pkdata, &size)) != CRYPT_OK) {
        return ret;
    }

    /* 2-byte id length in bits */
    idbits[0] = ((idlen * 8) >> 8) % 256;
    idbits[1] = (idlen * 8) % 256;

    len = hash_desc->hashsize;

    if (hash_desc->init(&hash_st)
        || hash_desc->process(&hash_st, idbits, sizeof(idbits))
        || hash_desc->process(&hash_st, (const unsigned char*)id, idlen)
        || hash_desc->process(&hash_st, pkdata, size)
        || hash_desc->done(&hash_st, out)) {
        return CRYPT_HASH_OVERFLOW;
    }

    *outlen = len;
    return CRYPT_OK;
}

/**
 * calculate H256(ZA||M)
 */
int sm2_compute_message_digest(const unsigned char *msg, size_t msglen, const char *id, size_t idlen,
        unsigned char *out, size_t *poutlen, const ecc_key *ec_key)
{
    int ret = CRYPT_OK;
    unsigned char za[SM3_DIGEST_LENGTH];
    size_t zalen = sizeof(za);
    unsigned int outlen;
    const struct ltc_hash_descriptor *hash_desc;
    hash_state hash_st;

    if (!msg || !id || !out || !poutlen || !ec_key) {
        return CRYPT_INVALID_ARG;
    }

    hash_desc = &hash_descriptor[find_hash("sm3")];
    outlen = hash_desc->hashsize;

    if ((ret = sm2_compute_id_digest(hash_desc, id, idlen, za, &zalen, ec_key)) != CRYPT_OK) {
        return ret;
    }

    /* H256(za || msg) */
    if (hash_desc->init(&hash_st)
        || hash_desc->process(&hash_st, za, zalen)
        || hash_desc->process(&hash_st, msg, msglen)
        || hash_desc->done(&hash_st, out)) {
        return CRYPT_HASH_OVERFLOW;
    }

    *poutlen = outlen;

    return ret;
}

#endif  /* LTC_SM2 */
