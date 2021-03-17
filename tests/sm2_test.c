/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
#include <tomcrypt_test.h>

#if defined(LTC_SM2) && defined(LTC_TEST_SM2)

const char* test_k = "81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029";
const char* test_x = "160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C94232";
const char* test_y = "4A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F";

int sm2_make_key_test(ecc_key *key)
{
    int            err;
    const ltc_ecc_curve* dp;

    LTC_ARGCHK(key         != NULL);

    if ((err = ecc_find_curve("SM2P256V1", &dp)) != CRYPT_OK)   { return err; }
    if ((err = ecc_set_curve(dp, key)) != CRYPT_OK)             { return err; }

    /* read test private key */
    if ((err = mp_read_radix(key->k, (char *)test_k, 16)) != CRYPT_OK)                          { goto error; }

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

int sm2_tests(void)
{
    ecc_key usera;
    unsigned char priv_key_hex[512];
    unsigned char pub_x_hex[512];
    unsigned char pub_y_hex[512];

    DO(sm2_make_key_test(&usera));
    mp_tohex(usera.k, (char*)priv_key_hex);
    mp_tohex(usera.pubkey.x, (char*)pub_x_hex);
    mp_tohex(usera.pubkey.y, (char*)pub_y_hex);

    if (compare_testvector(priv_key_hex, 64, test_k, 64, "SM2 private key", 0)) {
        return 1;
    }

    if (compare_testvector(pub_x_hex, 64, test_x, 64, "SM2 public key x", 0)) {
        return 1;
    }

    if (compare_testvector(pub_y_hex, 64, test_y, 64, "SM2 public key y", 0)) {
        return 1;
    }
    
    return 0;
}

#else

int sm2_tests(void)
{
    return CRYPT_NOP;
}

#endif
