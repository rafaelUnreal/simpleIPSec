#include <stdio.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string.h>

const char * dhgroup2 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
DH *dh;

void handleErrorsDH(){

printf("error \n");

} 

void initiateDH(){
	
if(NULL == (dh = DH_new())) handleErrorsDH();

BN_dec2bn(&dh->g, "2");
BN_hex2bn(&dh->p, dhgroup2 );
if(1 != DH_generate_key(dh)) handleErrorsDH();

}

void getPublicKey(unsigned char* to){
	
printf("Pub Key:\n");
BN_print_fp(stdout, dh->pub_key);
printf("\n");

BN_bn2bin(dh->pub_key, to);
	
}


//TODO function should not perform MALLOC here; it's not best practice
unsigned char * calculateSharedSecret(unsigned char *pubKey, int *secret_size){

int codes;
//int secret_size;

//printf("calculate shared secret\n");
//printf("KE 2:\n");
//printPayload(pubKey,  128);

/* Receive the public key from the peer. In this example we're just hard coding a value */
BIGNUM *pubkey = NULL;
BIGNUM *ret = NULL;
pubkey = BN_bin2bn(pubKey, 128, ret );

//BN_print_fp(stdout, pubkey);
//if(0 == (BN_dec2bn(&pubkey, pubKey))) handleErrors();

/* Compute the shared secret */
unsigned char *secret;
if(NULL == (secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(dh))))) handleErrors();

if(0 > ((*secret_size) = DH_compute_key(secret, pubkey, dh))) handleErrors();

/* Do something with the shared secret */
/* Note secret_size may be less than DH_size(privkey) */
printf("The shared secret is:\n");

BIO_dump_fp(stdout, secret, (*secret_size) );

//printf("shared secret size (calculateSharedSecret) %d\n", *(secret_size));
//printPayload(secret,(*secret_size) );

/* Clean up */
//OPENSSL_free(secret);
//BN_free(pubkey);
//DH_free(dh);

return secret;
}

//TODO function should not perform MALLOC here; it's not best practice
unsigned char *calculateHmacSha1(unsigned char *key, int key_len, unsigned char *data,int  data_len){
	
	unsigned char *digest = malloc(20);
	unsigned char *digest_static;
	
	
	digest_static = HMAC(EVP_sha1(), key, key_len, data, data_len, NULL, NULL);
	memcpy(digest,digest_static,20 );
	
	printf("CalculateHmacSHA\n");
	printf("key \n");
	printPayload(key, key_len);
	printf("\n");
	printf("Data: \n");
	printPayload(data, data_len);
	printf("\n");
	printf("Result Digest\n");
	printPayload(digest, 20);
	printf("\n");
	
	return digest;
	
}

//TODO remove malloc from within the function
unsigned char *calculateSHA1(unsigned char *data, unsigned int len){

	unsigned char *digest = malloc(20);

	unsigned int outlen;
	// makes all algorithms available to the EVP* routines
OpenSSL_add_all_algorithms();
// load the error strings for ERR_error_string
ERR_load_crypto_strings();

EVP_MD_CTX hashctx;
//const EVP_MD *hashptr = EVP_get_digestbyname("SHA256");
const EVP_MD *hashptr = EVP_get_digestbyname("SHA1");

EVP_MD_CTX_init(&hashctx);
EVP_DigestInit_ex(&hashctx, hashptr, NULL);
EVP_DigestUpdate(&hashctx, data, len);
EVP_DigestFinal_ex(&hashctx, digest, &outlen);


EVP_MD_CTX_cleanup(&hashctx);
	
	//SHA_CTX shactx;
	
	//SHA1_Init(&shactx);
   // SHA1_Update(&shactx, "2479027c1807b00a145bcdc990c9538c98d821f4a9d1951a1df6b899d9b9fece9cf997cf9788f806ab3cbd0c8284a5cc8e16b12b664c6f6d56352541daa8531667112736dfb14b145ff33557a2e818f77d35aa96a7ed6e9d9442b494063e8172d5b37e93cc5557b78694ceef8d70035851eff5b48c215795f0a0c30d439c0329b14d27387a7f86f3ed96c9c054bad8eaa7054997dbbeb5baa703b7dad1b5194f234a60c8c37616140ddbfa55df752b61305ff3377271289696621a1829aae843b2f7aedf675f395a4e7d10e108329af69d44581edd3e0f55816da30111d7f9ceac5716c89c92f6e265c6cfa829ed06ba198f33f3ff5d939e82361dddd5fe4590", len);
   // SHA1_Final(digest, &shactx);
	
	
	return digest;

}	
