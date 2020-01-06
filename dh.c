#include <stdio.h>
#include <openssl/dh.h>

char * calculateSharedSecret(const char *privateKey, const char *pubNonce){
DH *dh;
int codes;
int secret_size;

const char * dhgroup2 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

//hex equivalent to 123456
const char* userA_PrivateKey = "1E240";

void handleErrors(){

printf("error \n");

}

/* Generate the parameters to be used */
if(NULL == (dh = DH_new())) handleErrors();
//if(1 != DH_generate_parameters_ex(privkey, 2048, DH_GENERATOR_2, NULL)) handleErrors();

//if(1 != DH_check(privkey, &codes)) handleErrors();
//if(codes != 0)
//{
    /* Problems have been found with the generated parameters */
    /* Handle these here - we'll just abort for this example */
//    printf("DH_check failed\n");
//    abort();
//}

/* Generate the public and private key pair */



BN_dec2bn(&dh->g, "2");
BN_hex2bn(&dh->p, dhgroup2 );
BN_hex2bn(&dh->priv_key, userA_PrivateKey);

//if(1 != DH_generate_key(privkey)) handleErrors();

/* Send the public key to the peer.
 *  * How this occurs will be specific to your situation (see main text below) */


/* Receive the public key from the peer. In this example we're just hard coding a value */
BIGNUM *pubkey = NULL;
if(0 == (BN_dec2bn(&pubkey, pubNonce))) handleErrors();

/* Compute the shared secret */
unsigned char *secret;
if(NULL == (secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(dh))))) handleErrors();

if(0 > (secret_size = DH_compute_key(secret, pubkey, dh))) handleErrors();

/* Do something with the shared secret */
/* Note secret_size may be less than DH_size(privkey) */
printf("The shared secret is:\n");

BIO_dump_fp(stdout, secret, secret_size);

int i=0;

while(i < secret_size){

printf("%X",secret[i]);

i++;
}

/* Clean up */
OPENSSL_free(secret);
BN_free(pubkey);
DH_free(dh);

return secret;
}
