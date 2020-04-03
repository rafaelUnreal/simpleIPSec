#include <stdio.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>


const char * dhgroup2 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
DH *dh;

void handleErrors(){

printf("error \n");

} 

void initiateDH(){
	
if(NULL == (dh = DH_new())) handleErrors();

BN_dec2bn(&dh->g, "2");
BN_hex2bn(&dh->p, dhgroup2 );
if(1 != DH_generate_key(dh)) handleErrors();

}

void getPublicKey(unsigned char* to){
	
printf("Pub Key:\n");
BN_print_fp(stdout, dh->pub_key);
printf("\n");

BN_bn2bin(dh->pub_key, to);
	
}


// DH GROUP 2 FOR NOW
char * calculateSharedSecret(unsigned char *pubKey, int *secret_size){

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

unsigned char * calculateHmacSha1(unsigned char *key, int key_len, unsigned char *data,int  data_len){
	
	unsigned char *digest = malloc(20);
	unsigned char *digest_static;
	
	
	digest_static= HMAC(EVP_sha1(), key, key_len, data, data_len, NULL, NULL);
	memcpy(digest,digest_static,20 );
	
	
	printf("key \n");
	printPayload(key, key_len);
	printf("\n");
	printf("data \n");
	printPayload(data, data_len);
	printf("\n");
	printf("Result \n");
	printPayload(digest, 20);
	printf("\n");
	
	return digest;
	
}
