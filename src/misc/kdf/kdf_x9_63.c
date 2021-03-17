/* LibTomCrypt, modular cryptographic library -- Tom St Denis */

#include "tomcrypt_private.h"

#ifdef LTC_X963_KDF

/* ANS X9.63 KDF */

int x963_kdf(int hash_idx, const unsigned char *in,   unsigned long inlen,
                                 unsigned char *out,  unsigned long outlen)
{
    const struct ltc_hash_descriptor *hash_desc;
    hash_state md;
    unsigned long hashsize;
    int err;
    ulong32 counter = 1;
    ulong32 counter_be;
    unsigned char dgst[HASH_MAX_MD_SIZE];
    unsigned char *pout = out;
    size_t rlen = outlen;
    size_t len;

    /* make sure hash descriptor is valid */
    if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
        return err;
    }

    hash_desc = &hash_descriptor[hash_idx];
    hashsize = hash_desc->hashsize;

    while (rlen > 0) {
        LOAD32H(counter_be, (unsigned char *)&counter);
        counter++;

        if ((err = hash_desc->init(&md)) != CRYPT_OK) {
            return err;
        }
        if ((err = hash_desc->process(&md, in, inlen)) != CRYPT_OK) {
            return err;
        }
        if ((err = hash_desc->process(&md, (unsigned char*)&counter_be, sizeof(counter_be))) != CRYPT_OK) {
            return err;
        }
        if ((err = hash_desc->done(&md, dgst)) != CRYPT_OK) {
            return err;
        }

        len = hashsize <= rlen ? hashsize : rlen;
        XMEMCPY(pout, dgst, len);
        rlen -= len;
        pout += len;
    }

    return err;
}

#endif  /* LTC_X963_KDF */