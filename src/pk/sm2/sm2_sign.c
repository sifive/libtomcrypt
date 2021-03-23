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

#ifdef LTC_SM2

/**
 * Sign a message digest
 * @param dgst      The message digest to sign
 * @param dgstlen   The length of the digest
 * @param out       [out] The destination for the signature. it should init and free outside.
 * @param key       A private ECC key
 * @return CRYPT_OK if successful
 */
int sm2_sign(const unsigned char *dgst,  unsigned long dgstlen,
                struct sm2_sign_st *out, const ecc_key *key)
{
    return sm2_sign_ex(dgst, dgstlen, out, key, NULL);
}

#ifdef LTC_TEST_SM2
int sm2_make_key_test(const char *k, ecc_key *key);
#endif

/**
  Sign a message digest using the given random k.

  @param dgst      The message digest to sign
  @param dgstlen   The length of the digest
  @param out       [out] The destination for the signature. it should init and free outside.
  @param key       A private ECC key
  @param ik        hex random number. if NULL, random generate (optional)
  @return CRYPT_OK if successful
*/
int sm2_sign_ex(const unsigned char *dgst,  unsigned long dgstlen,
                struct sm2_sign_st *out, const ecc_key *key, const char *ik)
{
    ecc_key       pubkey;
    void          *e, *p, *rk;
    prng_state    yarrow_prng;
    int           err;
#ifdef LTC_TEST_SM2
    char buf[512];
#endif

    LTC_ARGCHK(dgst   != NULL);
    LTC_ARGCHK(out    != NULL);
    LTC_ARGCHK(out->r != NULL);
    LTC_ARGCHK(out->s != NULL);
    LTC_ARGCHK(key    != NULL);

    /* is this a private key? */
    if (key->type != PK_PRIVATE) {
        return CRYPT_PK_NOT_PRIVATE;
    }

    if ((err = rng_make_prng(128, find_prng("yarrow"), &yarrow_prng, NULL)) != CRYPT_OK) {
        return CRYPT_INVALID_PRNG;
    }

    /* init the bignums */
    if ((err = mp_init_multi(&e, &p, &rk, NULL)) != CRYPT_OK) {
        return err;
    }

    /* according GM/T 0003.1-2012 chapter 4.2.4 & 4.2.3 */ 
    /* get the hash and load it as a bignum into 'e' */
    if ((err = mp_read_unsigned_bin(e, (unsigned char *)dgst, dgstlen)) != CRYPT_OK)                { goto errnokey; }

    do {
        /* get random k and compute [k]G, similar to generating a public key */
        p = key->dp.order;
        if (!ik) {
            if ((err = ecc_copy_curve(key, &pubkey)) != CRYPT_OK)                                   { goto errnokey; }
            if ((err = ecc_generate_key(&yarrow_prng, find_prng("yarrow"), &pubkey)) != CRYPT_OK)   { goto error; }
        } else {
            if ((err = sm2_make_key_test(ik, &pubkey)) != CRYPT_OK)                                 { goto error; }
        }

#ifdef LTC_TEST_SM2
        memset(buf, 0, sizeof(buf));
        mp_tohex(pubkey.pubkey.x, buf);
        printf("x1: %s\n", buf);
#endif

        /* compute r = (e + x1) mod n */
        if ((err = mp_addmod(e, pubkey.pubkey.x, p, out->r)) != CRYPT_OK)       { goto error; }
#ifdef LTC_TEST_SM2
        memset(buf, 0, sizeof(buf));
        mp_tohex(out->r, buf);
        printf("r: %s\n", buf);
#endif
        /* r + k */
        if ((err = mp_add(out->r, pubkey.k, rk)) != CRYPT_OK)                   { goto error; }
        /* check r = 0 or r + k = n */
        if (mp_iszero(out->r) == LTC_MP_YES || mp_cmp(rk, p) == LTC_MP_EQ) {
            continue;
        }

        /* compute (1 + dA) ^ -1 */
        if ((err = mp_add_d(key->k, 1, out->s)) != CRYPT_OK)                    { goto error; } /* dA + 1 -> s */
        if ((err = mp_invmod(out->s, p, out->s)) != CRYPT_OK)                   { goto error; } /* (1 + dA) ^ -1 -> s */
#ifdef LTC_TEST_SM2
        memset(buf, 0, sizeof(buf));
        mp_tohex(out->s, buf);
        printf("(1 + dA) ^ -1: %s\n", buf);
#endif
        
        /* compute k - r * dA */
        if ((err = mp_mul(out->r, key->k, rk)) != CRYPT_OK)                      { goto error; } /* r * dA -> rk */
        if ((err = mp_sub(pubkey.k, rk, rk)) != CRYPT_OK)                        { goto error; } /* k - r * dA -> rk */

        /* compute (1 + dA) ^ -1 * (k - r * dA) mod n */
        if ((err = mp_mulmod(out->s, rk, p, out->s)) != CRYPT_OK)                { goto error; }

        if (mp_iszero(out->s) == LTC_MP_NO) {
            break;
        }
    } while (1);

error:
    ecc_free(&pubkey);
errnokey:
    mp_clear_multi(e, p, rk, NULL);
    return err;
}

#endif  /* LTC_SM2 */
