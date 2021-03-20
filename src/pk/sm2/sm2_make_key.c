/* LibTomCrypt, modular cryptographic library -- Tom St Denis */

/* Implements SM2 according to chinese standard GM/T 0003.1-2012
 *
 * ECC curve parameters refer to chinese standard GM/T 0003.5-2012
 */
#include "tomcrypt_private.h"
#include "tomcrypt_pk.h"
#include "tomcrypt_prng.h"

#ifdef LTC_SM2

/**
  Make a new SM2 key

  @param key          [out] Destination of the newly created key
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int sm2_make_key(ecc_key *key)
{
    int err;
    prng_state yarrow_prng;
    const ltc_ecc_curve* dp;

    if ((err = rng_make_prng(128, find_prng("yarrow"), &yarrow_prng, NULL)) != CRYPT_OK) {
        return err;
    }

    if ((err = ecc_find_curve("SM2P256V1", &dp)) != CRYPT_OK) {
        return err;
    }

    err = ecc_make_key_ex(&yarrow_prng, find_prng ("yarrow"), key, dp);

    return err;
}

#ifdef LTC_TEST_SM2

int sm2_make_key_test(const char* k, ecc_key *key)
{
    int            err;
    const ltc_ecc_curve* dp;

    LTC_ARGCHK(key         != NULL);

    if ((err = ecc_find_curve("SM2P256V1", &dp)) != CRYPT_OK)   { return err; }
    if ((err = ecc_set_curve(dp, key)) != CRYPT_OK)             { return err; }

    /* read test private key */
    if ((err = mp_read_radix(key->k, (char *)k, 16)) != CRYPT_OK)                          { goto error; }

    /* make the public key */
    if ((err = ltc_mp.ecc_ptmul(key->k, &key->dp.base, &key->pubkey, key->dp.A, key->dp.prime, 1)) != CRYPT_OK) {
        goto error;
    }
    key->type = PK_PRIVATE;

    /* success */
    err = CRYPT_OK;
    goto cleanup;

error:
   ecc_free(key);
cleanup:
   return err;
}

#endif  /* LTC_TEST_SM2 */

#endif  /* LTC_SM2 */
