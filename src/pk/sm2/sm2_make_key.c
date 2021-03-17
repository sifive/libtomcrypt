/* LibTomCrypt, modular cryptographic library -- Tom St Denis */

/* Implements SM2 according to chinese standard GM/T 0003.1-2012
 *
 * ECC curve parameters refer to chinese standard GM/T 0003.5-2012
 */
#include "tomcrypt.h"
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

#endif
