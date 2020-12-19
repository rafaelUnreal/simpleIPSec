#include <stdio.h>      // printf
#include <string.h>     // memset
#include <stdlib.h>     // exit(0);
#include <arpa/inet.h>  // inet_ntoa, ntohs
#include <sys/socket.h> // bind, recvfrom
#include <sys/queue.h>  // for Linkedlist
#include <unistd.h>     // close();
#include <stdarg.h> 	// for variadic function
#include "packet.h"
#include "encode.h"
#include "dh.h"
#include "config.h"

/*
This program was created for study purpose to implement ISAKMP/IPSec suite of protocols from scratch.
The main idea is not to have implement all ISAKMP/IPSec protocol, but only a basic working protocol with basic security cipher suite.

Author: Rafael Pinheiro
*/




/*TODO Apply a state peer info list node. Global state will only accept one remote peer at time */
unsigned int state = 0;


struct packet * initializePacket(struct packet *buf, u_int32_t size) {
	
	struct packet *p = malloc(sizeof(struct packet));
	if(p == NULL){
		abort();
	}
	p->data = (unsigned char *) malloc(sizeof(unsigned char) * size);
	p-> size=size;
	p->index=0;
	return p;
}



struct isakmp_attribute_node {
	struct isakmp_attribute isk_att;
	STAILQ_ENTRY(isakmp_attribute_node) pointers;
};

/* 
Mandatory supported SA payload types:
	- encryption algorithm
	- hash algorithm
	- authentication method
	- information about a group over which to do Diffie-Hellman.
*/

struct isakmp_crypto_policy {

	struct isakmp_attribute isk_att_encrypt;
	struct isakmp_attribute isk_att_hash;
	struct isakmp_attribute isk_att_auth;
	struct isakmp_attribute isk_att_dh;
	STAILQ_ENTRY(isakmp_crypto_policy) pointers;
};

void loadDefaultCryptoPolicy(){
	
	struct isakmp_crypto_policy crypto_policy_node;
	
	/* Todo: Implement config file that reads ISAKMP/IPSec configuration
	//setEncryption(crypto_policy_node->isk_att_encrypt,AES-CBC-128);
	//setHashing(crypto_policy_node->isk_att_encrypt,SHA-1);
	//setAuth(crypto_policy_node->isk_att_encrypt,PRE-SHARED-KEY);
	//setDH(crypto_policy_node->isk_att_encrypt,DH2);
	*/
}

struct isakmp_peer_info {

	unsigned char *preshared_key;
	unsigned char *NI;
	unsigned char *NR;
	unsigned int noncer_size;
	unsigned int noncei_size;
	unsigned int keyr_exchange_size;
	unsigned char *SKEYID;
	unsigned char *SKEYID_d;
	unsigned char *SKEYID_a;
	unsigned char *SKEYID_e;
	unsigned int prf_digest_size;
	unsigned char *gxi;
	unsigned char *gxr;
	unsigned char *gxy;
	unsigned char *HASH_I;
	unsigned char *HASH_R;
	unsigned int state;
	u_int8_t    CKY_I[8];
    u_int8_t    CKY_R[8];
	unsigned int encryption_algo;
	unsigned int hash_algo;
	unsigned int key_len; //in bytes
	unsigned int dh_group;
	unsigned int dh_group_size; // in bytes

	 STAILQ_ENTRY(isakmp_peer_info) pointers;


};


/* Queue and lists are initialized here */

/* Main list of nodes */
STAILQ_HEAD(isakmp_attribute_list, isakmp_attribute_node) head = STAILQ_HEAD_INITIALIZER(head);
/* List of ISAKMP attributes */
STAILQ_HEAD(isakmp_peer_list, isakm_peer_info) peer_head = STAILQ_HEAD_INITIALIZER(peer_head);
/* List of crypto(Phase 1) policies *TODO: Still to be implemented* */
STAILQ_HEAD(isakmp_crypto_policy_list, isakmp_crypto_policy) crypto_policy_head = STAILQ_HEAD_INITIALIZER(crypto_policy_head);

void die(char *s) { perror(s); exit(1);}

struct isakmp_peer_info * getNodeSPI(u_int8_t * CKY_I, u_int8_t *CKY_R){
	
	struct isakmp_peer_info *node;
	STAILQ_FOREACH(node, &peer_head, pointers) {
		if(strncmp(node->CKY_I,CKY_I,8) == 0 && strncmp(node->CKY_R,CKY_R,8) == 0){
			return node;
		}
	}
		return NULL;
}
int compareArrays(u_int8_t a[], u_int8_t b[], int n) {
	
  int i;
  for(i = 0; i <= n; i++) {
    if (a[i] != b[i]) return 0;
  }
  return 1;
}

void printPayload(unsigned char *data,unsigned int size){

        int i;
        for (i=0; i< size; i++){ printf(" %02X" ,(unsigned int) data[i]);
         if( i!=0 &&  i%16==0)  { 	 printf("\n"); }
        }

}

/* must be (int) and (unsigned char *) for each paramater pair */

unsigned char* concat(unsigned char *dest , int size, int count, ...) {
    va_list ap;
	unsigned char *concatTotal;
	unsigned char *concatTemp;
	int sumSize=0;
	int currentSize=0;
	int j;
	
    va_start(ap, count); /* Requires the last fixed parameter (to get the address) */
	

    for (j = 0; j < count/2; j++) {
		if(sumSize > size){ die("ConcatMem: memory overflow"); } 
		
		currentSize = va_arg(ap, int);
		concatTemp = va_arg(ap, unsigned char *);
		memcpy(dest+sumSize,concatTemp,currentSize);
		
		sumSize+=currentSize;

    }
    va_end(ap);
}

/*
TODO 1: Loop through all transforms and IKE attributes proposed based on internal policy
TODO 2: Support to Type/length/value attributes
TODO 3: Support to a config file for all ISAKMP packet fields(Cookie, reserverd fields, etc) instead of acting as proposal reflector

*/
struct packet* MM_R1_state(struct packet *p,struct isakmp_hdr isk_hdr){

	struct isakmp_sa isk_sa = { 0 };
	struct isakmp_proposal isk_prop  = { 0 };
    struct isakmp_transform isk_trans = { 0 };
	struct isakmp_attribute *isk_att;
	struct isakmp_attribute_node *isk_attp;
	struct isakmp_generic_payload isk_generic;

	unsigned int next_payload; 
	unsigned int position=0;
	unsigned int next_prop_payload;
	unsigned int next_trans_payload;
	unsigned int numAtt;
	int i;
	
	next_payload = isk_hdr.isa_np;
	position = sizeof(isk_hdr);
	printPayload(p->data, p->size);	
	
	while(next_payload!=0){
	
		switch(next_payload){

			case SA_ID:
			
				decodeIsakmpSa(p,&isk_sa);
				next_payload = isk_sa.isasa_np;
				decodeIsakmpProposal(p,&isk_prop);
				next_prop_payload = isk_prop.isap_np;	
				decodeIsakmpTransform(p,&isk_trans);
				next_trans_payload = isk_trans.isat_np; 
				numAtt = 0;

				/* TODO 1 */
				while(numAtt < (isk_trans.isat_length - sizeof(isk_trans))){
				
					isk_attp = calloc(0,sizeof(struct isakmp_attribute_node));     
					decodeIsakmpAttribute(p,&(isk_attp->isk_att));
					STAILQ_INSERT_TAIL(&head, isk_attp, pointers);
					numAtt= numAtt+sizeof(struct isakmp_attribute);
				}; 
				state = MM_R1;
				p->index = p->index + isk_trans.isat_length;
				next_payload = 0;
				
			break;
				case VENDOR_ID:
				break;
		}		
	}

	struct isakmp_peer_info * node_t;
	node_t = getNodeSPI(isk_hdr.isa_icookie, "\x00\x00\x00\x00\x00\x00\x00\00"); if(node_t == NULL){printf("invalid responder SPI, should be 00000000");}

	
	struct isakmp_attribute_node *n;
	struct packet *MM_R1_response_packet = malloc(sizeof(struct packet));
	
	u_int32_t  total_length = 0;
	u_int16_t  ike_att_length = 0;
	u_int16_t  length = 0;

	/* Proposal reflector: simply copying all information back to initiator */
	STAILQ_FOREACH(n, &head, pointers) { ike_att_length = ike_att_length + (sizeof(struct isakmp_attribute)); }

	total_length = (sizeof(struct isakmp_hdr) + sizeof(struct isakmp_sa) + sizeof(struct isakmp_proposal) + sizeof(struct isakmp_transform) + ike_att_length); 
	
	MM_R1_response_packet->data = malloc(sizeof(unsigned char)*total_length);
	MM_R1_response_packet->data_size=0;
	MM_R1_response_packet->size=total_length;
	MM_R1_response_packet->index=0;
	
	/* Response Packet details for MM_R1 */
	struct isakmp_hdr isk_hdr_response;
	struct isakmp_sa isk_sa_response;
	struct isakmp_proposal isk_prop_response;
	struct isakmp_transform isk_trans_response;
	struct isakmp_attribute isk_att_response;
	
	/* ISAKMP header */
	
	configSetIsakmpHdrResponseMM1(&isk_hdr_response,isk_hdr);
	
	//Adding cookie details to node list
	memcpy(node_t->CKY_R, isk_hdr_response.isa_rcookie,ISAKMP_COOKIE_SIZE) ;
	memcpy(node_t->CKY_I, isk_hdr.isa_icookie,ISAKMP_COOKIE_SIZE);


	
	/* ISAKMP security association */
	isk_sa_response.isasa_np = 0;
	isk_sa_response.isasa_reserved = isk_sa.isasa_reserved;
	length = ((total_length) - sizeof(isk_hdr));
	isk_sa_response.isasa_length = length;
	isk_sa_response.isasa_doi = isk_sa.isasa_doi;
	isk_sa_response.isasa_situation = isk_sa.isasa_situation;
	
	/* ISAKMP proposal */
	isk_prop_response.isap_np = isk_prop.isap_np;
	isk_prop_response.isap_reserved = isk_prop.isap_reserved;
	length = ((total_length) - sizeof(isk_hdr) - sizeof(isk_sa));
	isk_prop_response.isap_length = length;
	isk_prop_response.isap_proposal = isk_prop.isap_proposal;
	isk_prop_response.isap_protoid = isk_prop.isap_protoid;
	isk_prop_response.isap_spisize = isk_prop.isap_spisize;
	isk_prop_response.isap_notrans = 1;
	
	/* ISAKMP transforms */
	isk_trans_response.isat_np = isk_trans.isat_np;
	isk_trans_response.isat_reserved = isk_trans.isat_reserved;
	length = ((total_length) - sizeof(isk_hdr) - sizeof(isk_sa) - sizeof(isk_prop));
	isk_trans_response.isat_length = length;
	isk_trans_response.isat_transnum = isk_trans.isat_transnum;
	isk_trans_response.isat_transid = isk_trans.isat_transid;
	isk_trans_response.isat_reserved2 = isk_trans.isat_reserved2;
	
	/* Skiping header size, to enconde header as last */
    MM_R1_response_packet->index = ISAKMP_HDR_SIZE;
	
	encodeIsakmpSa(MM_R1_response_packet,&isk_sa_response);
	encodeIsakmpProposal(MM_R1_response_packet,&isk_prop_response);
	encodeIsakmpTransform(MM_R1_response_packet,&isk_trans_response);
	STAILQ_FOREACH(n, &head, pointers) { encodeIsakmpAttribute(MM_R1_response_packet,&(n->isk_att)); }
		
	MM_R1_response_packet->index = 0;
	isk_hdr_response.isa_length = MM_R1_response_packet->data_size + ISAKMP_HDR_SIZE;
	encodeIsakmpHeader(MM_R1_response_packet,&isk_hdr_response);
	
	/* Peer node details agreed as key size */
	node_t->keyr_exchange_size = 128;
	node_t->key_len = 16;
	node_t->state = MM_R2;
	
	#ifdef DEBUG
	printf("SIZE: %d \n", MM_R1_response_packet->data_size);
	printf("Print response \n");
	printPayload(MM_R1_response_packet->data, MM_R1_response_packet->size);	
	printf("\n");
	#endif
	
	return MM_R1_response_packet;
}

struct packet *MM_R2_state(struct packet *p,struct isakmp_hdr isk_hdr, struct isakmp_peer_info *node){

	struct isakmp_nonce isk_nonce;
	struct isakmp_key_exchange isk_keyex;
	u_int16_t nonceSize=0;
	u_int16_t pubKeySize=0;
	
	unsigned int next_payload;
	next_payload = isk_hdr.isa_np;
	while(next_payload!=0){
		switch(next_payload){
			case KE:
	
				decodeIsakmpGeneric(p,&(isk_keyex.isk_hdr_generic));
				isk_keyex.isakey_data = (unsigned char *) malloc(sizeof(unsigned char) * (isk_keyex.isk_hdr_generic.isagen_length - sizeof(struct isakmp_generic_payload)));
				decodeChunk(p,isk_keyex.isakey_data, (isk_keyex.isk_hdr_generic.isagen_length - sizeof(struct isakmp_generic_payload)));
				
				#ifdef DEBUG
				printf("KE :\n");
				printPayload(isk_keyex.isakey_data,  (isk_keyex.isk_hdr_generic.isagen_length - sizeof(struct isakmp_generic_payload)));
				printf("\n");
				#endif 
				
				next_payload = isk_keyex.isk_hdr_generic.isagen_np;
				state = MM_R2;
			case NONCE:
			
				decodeIsakmpGeneric(p,&(isk_nonce.isk_hdr_generic));
				isk_nonce.isan_data = (unsigned char *) malloc(sizeof(unsigned char) * (isk_nonce.isk_hdr_generic.isagen_length - sizeof(struct isakmp_generic_payload))+1);
				nonceSize = (isk_nonce.isk_hdr_generic.isagen_length - sizeof(struct isakmp_generic_payload));
				node->noncei_size = nonceSize;
				node->noncer_size = nonceSize;
				decodeChunk(p,isk_nonce.isan_data, (isk_nonce.isk_hdr_generic.isagen_length - sizeof(struct isakmp_generic_payload)));
				
				#ifdef DEBUG
				printf("NONCE \n");
				printPayload(isk_nonce.isan_data,  (isk_nonce.isk_hdr_generic.isagen_length - sizeof(struct isakmp_generic_payload)));
				printf("\n");
				#endif 
				next_payload = isk_nonce.isk_hdr_generic.isagen_np;
				state = MM_R2;
				next_payload = 0;
			break;
		}		
	}
	
	#ifdef DEBUG
	printf("\n");
	printf("initialize MM_R2_state \n");
	#endif
	struct packet *MM_R2_response_packet = malloc(sizeof(struct packet));
	
	u_int32_t  total_length = 0;
	u_int16_t  length = 0;

	/* Initiate DH Group 2 statically configured for now. TODO: Accept and calculate multiple DH groups */
	initiateDH();

	/* MM_R2 response message */
	struct isakmp_hdr isk_hdr_response;
	struct isakmp_nonce isk_nonce_response;
	struct isakmp_key_exchange isk_keyex_response;

	/* Reflecting same DH group being proposed. Yet only DH group 2 is supported for now  */
	isk_keyex_response.isakey_data = (unsigned char *) malloc(sizeof(unsigned char) * (isk_keyex.isk_hdr_generic.isagen_length - sizeof(struct isakmp_generic_payload)));
	node->dh_group_size = isk_keyex.isk_hdr_generic.isagen_length - sizeof(struct isakmp_generic_payload);
	isk_nonce_response.isan_data = (unsigned char *) malloc(node->noncer_size);
	memcpy(isk_nonce_response.isan_data, "\x42\xec\xee\x52\xf0\x42\x12\x2b\x9a\xfc\xaf\xa3\x96\xfc\x3f\xb1",node->noncer_size);
	getPublicKey(isk_keyex_response.isakey_data);

	node->gxi = isk_keyex.isakey_data;
	node->gxr = isk_keyex_response.isakey_data;

	//Calculate keying material:
	
	unsigned int secret_size = 0;
	//PPRESHARED KEY STATIC ALLOCATED FOR TEST PURPOSES
	unsigned int preSharedKeySize=3;
	node->preshared_key = malloc(preSharedKeySize);
	memcpy(node->preshared_key,"\x31\x32\x33", preSharedKeySize);
	node->gxy = calculateSharedSecret(isk_keyex.isakey_data, &secret_size);


	/* SKEYID = prf(pre-shared-key, Ni_b | Nr_b) */
	/* All information for nonce initiator and response size are stored at node peer list */
	/* SHA1 is static used for now TODO use any hash function as prf */
	unsigned int nonce_ir_size = node->noncei_size+node->noncer_size;
	unsigned char *dataConcat = malloc(nonce_ir_size); // size of two nonces concatenated
	concat(dataConcat,nonce_ir_size,4,node->noncei_size,isk_nonce.isan_data,node->noncer_size,isk_nonce_response.isan_data);
	
	node->SKEYID = calculateHmacSha1(node->preshared_key,preSharedKeySize,dataConcat,node->noncei_size+node->noncer_size);
	free(dataConcat);
	
	
	node->prf_digest_size = 20;

	/* SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0) */
	unsigned int prf_skeyidd_size = secret_size+ISAKMP_COOKIE_SIZE+ISAKMP_COOKIE_SIZE+1;
	unsigned char *dataConcat2 = malloc(prf_skeyidd_size);
	
	concat(dataConcat2,prf_skeyidd_size,8,secret_size,node->gxy,ISAKMP_COOKIE_SIZE,node->CKY_I,ISAKMP_COOKIE_SIZE,node->CKY_R,1,"\x0");
	free(dataConcat2);
	node->SKEYID_d = calculateHmacSha1(node->SKEYID,node->prf_digest_size,dataConcat2,prf_skeyidd_size);

	/* SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1) */
	unsigned char *dataConcat3 = malloc(secret_size+node->prf_digest_size+ISAKMP_COOKIE_SIZE+ISAKMP_COOKIE_SIZE+1);
	memcpy(dataConcat3,node->SKEYID_d,node->prf_digest_size);
	memcpy(dataConcat3+node->prf_digest_size,node->gxy,secret_size);
	memcpy(dataConcat3+secret_size+node->prf_digest_size,node->CKY_I,ISAKMP_COOKIE_SIZE);
	memcpy(dataConcat3+secret_size+node->prf_digest_size+ISAKMP_COOKIE_SIZE,node->CKY_R,ISAKMP_COOKIE_SIZE);
	memcpy(dataConcat3+secret_size+node->prf_digest_size+ISAKMP_COOKIE_SIZE+ISAKMP_COOKIE_SIZE,"\x1",1);
	node->SKEYID_a = calculateHmacSha1(node->SKEYID,node->prf_digest_size,dataConcat3,secret_size+node->prf_digest_size+ISAKMP_COOKIE_SIZE+ISAKMP_COOKIE_SIZE+1);

	/* SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2) */
	unsigned char *dataConcat4 = malloc(secret_size+node->prf_digest_size+ISAKMP_COOKIE_SIZE+ISAKMP_COOKIE_SIZE+1);
	memcpy(dataConcat4,node->SKEYID_a,node->prf_digest_size);
	memcpy(dataConcat4+node->prf_digest_size,node->gxy,secret_size);
	memcpy(dataConcat4+secret_size+node->prf_digest_size,node->CKY_I,ISAKMP_COOKIE_SIZE);
	memcpy(dataConcat4+secret_size+node->prf_digest_size+ISAKMP_COOKIE_SIZE,node->CKY_R,ISAKMP_COOKIE_SIZE);
	memcpy(dataConcat4+secret_size+node->prf_digest_size+ISAKMP_COOKIE_SIZE+ISAKMP_COOKIE_SIZE,"\x2",1);
	node->SKEYID_e = calculateHmacSha1(node->SKEYID,node->prf_digest_size,dataConcat4,secret_size+node->prf_digest_size+ISAKMP_COOKIE_SIZE+ISAKMP_COOKIE_SIZE+1);

	#ifdef DEBUG
	printf("SKEYID \n");
	printPayload(node->SKEYID, node->prf_digest_size);
	printf("\n");

	printf("SKEYID_d	 \n");
	printPayload(node->SKEYID_d, node->prf_digest_size);
	printf("\n");

	printf("SKEYID_a	 \n");
	printPayload(node->SKEYID_a, node->prf_digest_size);
	printf("\n");

	printf("SKEYID_e	 \n");
	printPayload(node->SKEYID_e, node->prf_digest_size);
	printf("\n");
	#endif

	total_length = (sizeof(struct isakmp_hdr) + sizeof(struct isakmp_generic_payload) + sizeof(struct isakmp_generic_payload) + 128 + node->noncer_size); 

	/*Response Packet for MM_R2 */
	MM_R2_response_packet->data = malloc(sizeof(unsigned char)*total_length);

	MM_R2_response_packet->size=total_length;
	MM_R2_response_packet->index=0;
	MM_R2_response_packet->data_size=0;

	memcpy(isk_hdr_response.isa_icookie, isk_hdr.isa_icookie, sizeof(u_int8_t) * ISAKMP_COOKIE_SIZE);
	memcpy(isk_hdr_response.isa_rcookie, "\x11\x11\x11\x11\x11\x11\x11\x11", ISAKMP_COOKIE_SIZE);
	
	isk_hdr_response.isa_np = isk_hdr.isa_np;
	isk_hdr_response.isa_version = isk_hdr.isa_version;
	isk_hdr_response.isa_xchg = isk_hdr.isa_xchg;
	isk_hdr_response.isa_flags = isk_hdr.isa_flags;
	isk_hdr_response.isa_msgid = isk_hdr.isa_msgid;
	isk_hdr_response.isa_length = total_length;
	
	encodeIsakmpHeader(MM_R2_response_packet,&isk_hdr_response);
	
	#ifdef DEBUG
	printf("encode isakmp header \n");
	printf("Print ISAKMP \n");
	printPayload(MM_R2_response_packet->data, MM_R2_response_packet->size);	
	printf("\n");
	#endif
	isk_keyex_response.isk_hdr_generic.isagen_np = isk_keyex.isk_hdr_generic.isagen_np;
	isk_keyex_response.isk_hdr_generic.isagen_reserved = isk_keyex.isk_hdr_generic.isagen_reserved;
	isk_keyex_response.isk_hdr_generic.isagen_length = isk_keyex.isk_hdr_generic.isagen_length;
	
	
	encodeIsakmpGeneric(MM_R2_response_packet,&isk_keyex.isk_hdr_generic);
	#ifdef DEBUG
	printf("encode isakmp generic \n");
	printf("encode chunk  \n");	
	#endif
	encodeChunk(MM_R2_response_packet,isk_keyex_response.isakey_data, node->keyr_exchange_size);
	
	isk_nonce_response.isk_hdr_generic.isagen_np = isk_nonce.isk_hdr_generic.isagen_np;
	isk_nonce_response.isk_hdr_generic.isagen_reserved = isk_nonce.isk_hdr_generic.isagen_reserved;
	isk_nonce_response.isk_hdr_generic.isagen_length = isk_nonce.isk_hdr_generic.isagen_length;
	
	encodeIsakmpGeneric(MM_R2_response_packet,&isk_nonce.isk_hdr_generic);
	encodeChunk(MM_R2_response_packet,isk_nonce_response.isan_data, node->noncer_size);
	node->state = MM_R3;
	
	#ifdef DEBUG
	printf("SIZE: %d \n", MM_R2_response_packet->data_size);
	printf("Print response \n");
	printPayload(MM_R2_response_packet->data, MM_R2_response_packet->size);	
	printf("\n");
	#endif
	
	return MM_R2_response_packet;
}


struct packet *MM_R3_state(struct packet *p,struct isakmp_hdr isk_hdr, struct isakmp_peer_info *node)
{
	
	//Only supports AES128 or AES 256
	unsigned char dh_concat[255];
	unsigned char skeyidETrunc[16];  
	unsigned char *iv;
	unsigned char ivTrunc[16]; 
	int encrypted_len=0;
	unsigned char *decrypted_data;
	
	unsigned int next_payload;
	
	struct isakmp_ipsec_id isk_id;
	struct isakmp_hash isk_hash;
	
	memcpy(dh_concat,node->gxi,node->dh_group_size);
	memcpy((dh_concat+node->dh_group_size),node->gxr,node->dh_group_size);
	
	printf("Concat DH \n");
	printPayload(dh_concat,node->dh_group_size+node->dh_group_size);
	printf("\n");
	
	iv = calculateSHA1(dh_concat,node->dh_group_size+node->dh_group_size); // Recent change to remove null at end of array
	
	memcpy(ivTrunc,iv,node->key_len);
	memcpy(skeyidETrunc,node->SKEYID_e,node->key_len);


	encrypted_len = (isk_hdr.isa_length) - ISAKMP_HDR_SIZE; //SIZE OF ISAKMP HEADER EQUALS 28
	decrypted_data = malloc(encrypted_len);
	
	decrypt(p->data+ISAKMP_HDR_SIZE,encrypted_len,skeyidETrunc,ivTrunc ,decrypted_data);
	printf("IV: \n");
	printPayload(iv,node->key_len);	
	printf("\n");
	
	printf("MM_R3 PAYLOAD: \n");
	printPayload(p->data,p->size);	
	printf("\n");
	printf("encrypted len: %d \n",encrypted_len);
	
	printf("DECRYPTED DATA: \n");
	printPayload(decrypted_data,encrypted_len);
	printf("\n");
	
	memcpy(p->data+ISAKMP_HDR_SIZE, decrypted_data,encrypted_len);
	
	next_payload = isk_hdr.isa_np;
	
	while(next_payload!=0){
	
		switch(next_payload){

			case ID:
	
				decodeIsakmpId(p,&isk_id);
				unsigned int id_hdr_size = isk_id.isk_ipsec_id.isaiid_length - ISAKMP_ID_HDR;
				isk_id.id_data = (unsigned char *) malloc(sizeof(unsigned char) * id_hdr_size);

				decodeChunk(p,isk_id.id_data, id_hdr_size);
				printf("ID payload :\n");
				printPayload(isk_id.id_data,  id_hdr_size);
				printf("\n");
				next_payload = isk_id.isk_ipsec_id.isaiid_np;
				state = MM_R3;
			case HASH:
			
				decodeIsakmpGeneric(p,&(isk_hash.isk_hdr_generic));
				isk_hash.hash_data = (unsigned char *) malloc(sizeof(unsigned char) * node->prf_digest_size);				
				
				decodeChunk(p,isk_hash.hash_data, node->prf_digest_size );
				printf("HASH \n");
				printPayload(isk_hash.hash_data,  node->prf_digest_size);

				next_payload = isk_hash.isk_hdr_generic.isagen_np;
				state = MM_R3;
		
				next_payload = 0;	
			break;

		}		
	}
	
	/* SAi_b is the entire body of the SA payload (minus the ISAKMP
     generic header)-- i.e. the DOI, situation, all proposals and all
     transforms offered by the Initiator.
	 */
	 
	/* HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b ) */
	//unsigned int concat_size = node->secret_size + node->secret_size + ISAKMP_COOKIE_SIZE + ISAKMP_COOKIE_SIZE
	//unsigned char *dataConcat 
	//node->HASH_R = calculateHmacSha1(node->SKEYID,

}

struct packet* processPacket(struct packet *p, u_int16_t size){
	
	struct isakmp_peer_info *node;
	struct isakmp_hdr isk_hdr = {0};
	struct packet *result;
	
	//memcpy((unsigned char*)&isk_hdr,data,sizeof(isk_hdr));	// Still need to validate ISKMP header
	decodeIsakmpHeader(p,&isk_hdr);

	STAILQ_FOREACH(node, &peer_head, pointers) {

			if(strncmp(node->CKY_I,isk_hdr.isa_icookie,ISAKMP_COOKIE_SIZE) == 0 && strncmp(node->CKY_R,isk_hdr.isa_rcookie,ISAKMP_COOKIE_SIZE) == 0 ){
				// IF EXIST SEND TO THE CORRECT STATE
			
				switch(node->state){

					
					case MM_R2:
						printf("MM_R2\n");
						result = MM_R2_state(p,isk_hdr,node);
						return result;
					
					break;
					
					case MM_R3:
						printf("MM_R3\n");
						result = MM_R3_state(p,isk_hdr,node);
					break;
					
					
					case QM_R1:
					
					break;
					
					case QM_R2:
					
					break;
					
					
					default:
						printf("error\n");
						return NULL;
					break;
				}
			
			
			}

     }
		
	struct isakmp_peer_info *newPeer =  malloc(sizeof(struct isakmp_peer_info));
	memcpy(newPeer->CKY_I,isk_hdr.isa_icookie,ISAKMP_COOKIE_SIZE);
	memcpy(newPeer->CKY_R,isk_hdr.isa_rcookie,ISAKMP_COOKIE_SIZE);
	
	STAILQ_INSERT_TAIL(&peer_head, newPeer, pointers);
	printf("MM_R1\n");
	result = MM_R1_state(p,isk_hdr);
	return result;
	
	
}

//bool mainMode_inI1(struct isakmp_hdr){

//}

void startIpsec(){
	
	
  /*
       sockaddr_in is a utility for sockaddr that deals with internet (in) based addresses. The struct looks like:

       struct sockaddr_in {
           short int          sin_family;  // Address family
           unsigned short int sin_port;    // Port number
           struct in_addr     sin_addr;    // Internet address
           unsigned char      sin_zero[8]; // Same size as struct sockaddr
        }; 

        **Note**: that sin_zero (which is included to pad the structure to the length of a struct sockaddr) 
          should be set to all zeros with the function memset().
     */
    struct sockaddr_in si_me, si_other;

    int s, slen = sizeof(si_other) , recv_len;
	
    // initialize single linked list of IKE Attributes being received.
    STAILQ_INIT(&head);

    // buffer to hold packets. If incoming data is > BUFLEN then the bytes will
    // be dropped.
	unsigned char buf[BUFLEN] = {0};
	
	//struct packet to receive all data in buffer
	struct packet *p;
	p = calloc(0,sizeof(struct packet));

    // create a UDP socket (SOCK_DGRAM)
    if ((s=socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        die("socket");
    }

    // zero out the structure entire structre.  Alternatively, we could of zero
    // out just si_me.sin_zero with: memset(&(my_addr.sin_zero), '\0', 8);
    memset((char *) &si_me, 0, sizeof(si_me));

    // Always use AF_INET.  AF_INET is only used by the kernel and doesn't need
    // to be in network byte order.
    si_me.sin_family = AF_INET;
    // Convert to proper byte form.
    // Remember: put your bytes in Network Byte Order before you put them on the network. Be portable!
    si_me.sin_port = htons(PORT); // setting to 0 would have system pick port.
    // Use my own port.
    // Technically this is 0 and doesn't need the call to htonl 
    // but this will improve portability and most compilers will avoid anyways.
    si_me.sin_addr.s_addr = htonl(INADDR_ANY); 

    // bind socket to port
    if( bind(s , (struct sockaddr*)&si_me, sizeof(si_me) ) == -1)
    {
        die("bind");
    }

    // keep listening for data
    while(1)
    {
        // give user a heads up
        printf("Waiting for data...");
        //fflush(stdout);

        // try to receive some data, this is a blocking call
        if ((recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == -1)
        {
            die("recvfrom()");
        }
		else{
			//Received some data
			p->size = recv_len;
			p->data = buf;
			p->index = 0;
			
		}
        
        /*
         Some machines store their numbers internally in Network Byte Order (Big-Endian Byte Order),
         some don't.  htons => Host To Network Short. ntohs => Network To Host Short
        */
        printf(
          "Received packet from %s:%d\n", 
          // network to ascii => prints network binary to dot IP notation
          inet_ntoa(si_other.sin_addr), 
          // network to host short
          ntohs(si_other.sin_port)
        );
	//printPayload(buf,recv_len);
	struct packet* result = processPacket(p,p->size);
	if(result!=NULL){

	   if (sendto(s, result->data, result->size, 0, (struct sockaddr*) &si_other, slen) == -1)
	        {
	                die("sendto()");
	         }
	}

    }
    close(s);
}



int main(void)
{
	printf("Simple IPsec by Rafael P.\n");
	//config parse
	
	if(initConfig()){ perror("Config File Error\n"); return 0; }
	startIpsec();
    return 0;
}
