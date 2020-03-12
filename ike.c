/*
    Simple udp server
*/
#include <stdio.h>      // printf
#include <string.h>     // memset
#include <stdlib.h>     // exit(0);
#include <arpa/inet.h>  // inet_ntoa, ntohs
#include <sys/socket.h> // bind, recvfrom
#include <sys/queue.h>  // for Linkedlist
#include <unistd.h>     // close();
#include "packet.h"
#include "encode.h"
/*
  As UDP always returns at most one UDP packet (even if multiple are in the
  socket buffer) and no UDP packet can be above 64 KB (an IP packet may at most
  be 64 KB, even when fragmented), using a 64 KB buffer is absolutely safe and
  guarantees, that you never lose any data during a recv on an UDP socket.

  1024 * 64 = 65536
*/
#define BUFLEN 65536 // max buffer length
#define PORT 500    // hardcoded port


//ISAKMP PAYLOAD ID

//NONE                           0
#define SA_ID      1
#define SA_PROP_ID  2
#define TRANS_ID 3
#define KE  4
#define NONCE 10
#define VENDOR_ID 55
//Identification (ID)            5


// IKEv1 states
#define NO_STATE  0
#define MM_R1  1
#define MM_R2  2
#define MM_R3  3
#define MM_I1  4
#define MM_I2  5
#define MM_I3  6

#define QM_R1  7
#define QM_R2  8
#define QM_I1  9
#define QM_I2  10

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
// ISAKMP HEADER



struct isakmp_attribute_node {

	struct isakmp_attribute isk_att;
	STAILQ_ENTRY(isakmp_attribute_node) pointers;

};
// - encryption algorithm
//
// - hash algorithm
//
// - authentication method
//
//- information about a group over which to do Diffie-Hellman.
//
//Above attributes are mandatory

struct isakmp_crypto_policy {

	struct isakmp_attribute isk_att_encrypt;
	struct isakmp_attribute isk_att_hash;
	struct isakmp_attribute isk_att_auth;
	struct isakmp_attribute isk_att_dh;
	STAILQ_ENTRY(isakmp_crypto_policy) pointers;
};

void loadDefaultCryptoPolicy(){
	
	struct isakmp_crypto_policy crypto_policy_node;
	
	//TODO
	//setEncryption(crypto_policy_node->isk_att_encrypt,AES-CBC-128);
	//setHashing(crypto_policy_node->isk_att_encrypt,SHA-1);
	//setAuth(crypto_policy_node->isk_att_encrypt,PRE-SHARED-KEY);
	//setDH(crypto_policy_node->isk_att_encrypt,DH2);
	
}

struct isakmp_peer_info {

	unsigned char *preshared_key;
	unsigned char *NI;
	unsigned char *NR;
	unsigned char *SKEYID;
	unsigned char *SKEYID_d;
	unsigned char *SKEYID_a;
	unsigned char *SKEYID_e;
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
	unsigned int key_len;
	unsigned int dh_group;

	 STAILQ_ENTRY(isakmp_peer_info) pointers;


};


//Queue and lists are initialized here

STAILQ_HEAD(isakmp_attribute_list, isakmp_attribute_node) head = STAILQ_HEAD_INITIALIZER(head);
STAILQ_HEAD(isakmp_peer_list, isakm_peer_info) peer_head = STAILQ_HEAD_INITIALIZER(peer_head);
STAILQ_HEAD(isakmp_crypto_policy_list, isakmp_crypto_policy) crypto_policy_head = STAILQ_HEAD_INITIALIZER(crypto_policy_head);


// die prints the error message on stderr and exits with a non-success code
void die(char *s)
{
    perror(s);
    exit(1);
}

struct isakmp_peer_info * getNodeSPI(u_int8_t * CKY_I, u_int8_t *CKY_R){
	
	
	struct isakmp_peer_info *node;
	
	STAILQ_FOREACH(node, &peer_head, pointers) {
		
		if(strncmp(node->CKY_I,CKY_I,8) == 0 && strncmp(node->CKY_R,CKY_R,8) == 0){
			printf("EQUALS\n");
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

        for (i=0; i< size; i++){

         printf(" %02X" ,(unsigned int) data[i]);
	
         if( i!=0 &&  i%16==0)  {
	
       	 printf("\n");
        }
        }
        //printf("Data: %x\n" ,(unsigned int) buf[0]);
        //memset(buf,0,BUFLEN);
        //
}

//receive struct packet p and return response in struct packet 
struct packet* MM_R1_state(struct packet *p,struct isakmp_hdr isk_hdr){

	struct isakmp_sa isk_sa = { 0 };
	struct isakmp_proposal isk_prop  = { 0 };
    struct isakmp_transform isk_trans = { 0 };
	struct isakmp_attribute *isk_att;
	struct isakmp_attribute_node *isk_attp;
	struct isakmp_generic_payload isk_generic;


	unsigned int next_payload; // ISAKMP header has to have at least 1 SA
	unsigned int position=0;
	unsigned int next_prop_payload;
	unsigned int next_trans_payload;
	unsigned int numAtt;
	
	//INITIALIZE HEAD OF LIST
	//STAILQ_INIT(&head); 
		
	
	next_payload = isk_hdr.isa_np;
	position = sizeof(isk_hdr);
	printPayload(p->data, p->size);	
	
	// THIS CODE MUST BE IN A DISTINCT FUNCTION FOR MM_R1
	while(next_payload!=0){
	
		switch(next_payload){

			case SA_ID:
			
				//Decode ISAKMP SA
				decodeIsakmpSa(p,&isk_sa);
				next_payload = isk_sa.isasa_np;
				//Decode IsakmpProposal
				decodeIsakmpProposal(p,&isk_prop);
				//TODO LOOP THROUGH ALL PROPOSALS
				next_prop_payload = isk_prop.isap_np;	
				decodeIsakmpTransform(p,&isk_trans);
				//memcpy((unsigned char*)&isk_trans,(data+(sizeof(isk_hdr)+sizeof(isk_sa)+sizeof(isk_prop))),sizeof(isk_trans));
				//TODO LOOP THROUGH ALL TRANSFORMS
				next_trans_payload = isk_trans.isat_np;

				//LOOP THROUGH ALL IKE ATTRIBUTES
				numAtt = 0;
	
				//printf("ISAKMP ATTRIBUTES %d \n", isk_trans.isat_length);
				while(numAtt < (isk_trans.isat_length - sizeof(isk_trans))){

					isk_attp = calloc(0,sizeof(struct isakmp_attribute_node));      /* Insert at the head. */
					decodeIsakmpAttribute(p,&(isk_attp->isk_att));
					STAILQ_INSERT_TAIL(&head, isk_attp, pointers);
					numAtt+=4; // Size of basic IKE attribute
				//printf("segmentation 3\n");
				}; 
				state = MM_R1;
				//TEST
				p->index = p->index + 36;
				next_payload = 0;
				
			break;

				case VENDOR_ID:
				
				break;


		}		


	}
	//printPayload(isk_hdr.isa_icookie,8);
	//UPDATE LIST OF NODES WITH RESPONDER SPI
	struct isakmp_peer_info * node_t;
	node_t = getNodeSPI(isk_hdr.isa_icookie, "\x00\x00\x00\x00\x00\x00\x00\00"); if(node_t == NULL){printf("invalid responder SPI, should be 00000000");}
	
	else{
		memcpy(node_t->CKY_R, "\x11\x11\x11\x11\x11\x11\x11\x11",8) ;
		
		printf("Responder SPI \n");
		printPayload(node_t->CKY_R,8);
	}
	
	struct isakmp_attribute_node *n;
	
	struct packet *MM_R1_response_packet = malloc(sizeof(struct packet));
	
	
	u_int32_t  total_length = 0;
	u_int16_t  ike_att_length = 0;
	u_int16_t  length = 0;

	
	//Responding with same IKE attributes and calculate length for transform length
	STAILQ_FOREACH(n, &head, pointers) {
	ike_att_length = ike_att_length + (sizeof(struct isakmp_attribute));
        //printf("PRINT IKE ATTRIBUTE LIST %04X \n",htons(n->isk_att.isaat_af_type));
        //printf("PRINT IKE ATTRIBUTE LIST %04X \n",htons(n->isk_att.isaat_lv));
        }

	
	//Calculator HDR ISK total length
	
	total_length = (sizeof(struct isakmp_hdr) + sizeof(struct isakmp_sa) + sizeof(struct isakmp_proposal) + sizeof(struct isakmp_transform) + ike_att_length); 
	

	MM_R1_response_packet->data = malloc(sizeof(unsigned char)*total_length);
	
	MM_R1_response_packet->size=total_length;
	MM_R1_response_packet->index=0;
	
	//Prepare response packet
	
	struct isakmp_hdr isk_hdr_response;
	struct isakmp_sa isk_sa_response;
	struct isakmp_proposal isk_prop_response;
	struct isakmp_transform isk_trans_response;
	struct isakmp_attribute isk_att_response;
	
	
	//isk_hdr_response.isa_icookie = isk_hdr.isa_icookie;
	memcpy(isk_hdr_response.isa_icookie, isk_hdr.isa_icookie, sizeof(u_int8_t) * 8);
	memcpy(isk_hdr_response.isa_rcookie, "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
	isk_hdr_response.isa_np = isk_hdr.isa_np;
	isk_hdr_response.isa_version = isk_hdr.isa_version;
	isk_hdr_response.isa_xchg = isk_hdr.isa_xchg;
	isk_hdr_response.isa_flags = isk_hdr.isa_flags;
	isk_hdr_response.isa_msgid = isk_hdr.isa_msgid;
	isk_hdr_response.isa_length = total_length;

	encodeIsakmpHeader(MM_R1_response_packet,&isk_hdr_response);
	
	isk_sa_response.isasa_np = 0;
	isk_sa_response.isasa_reserved = isk_sa.isasa_reserved;
	length = ((total_length) - sizeof(isk_hdr));
	isk_sa_response.isasa_length = length;
	isk_sa_response.isasa_doi = isk_sa.isasa_doi;
	isk_sa_response.isasa_situation = isk_sa.isasa_situation;
	
	encodeIsakmpSa(MM_R1_response_packet,&isk_sa_response);

	isk_prop_response.isap_np = isk_prop.isap_np;
	isk_prop_response.isap_reserved = isk_prop.isap_reserved;
	length = ((total_length) - sizeof(isk_hdr) - sizeof(isk_sa));
	isk_prop_response.isap_length = length;
	isk_prop_response.isap_proposal = isk_prop.isap_proposal;
	isk_prop_response.isap_protoid = isk_prop.isap_protoid;
	isk_prop_response.isap_spisize = isk_prop.isap_spisize;
	isk_prop_response.isap_notrans = 1;
	
	encodeIsakmpProposal(MM_R1_response_packet,&isk_prop_response);
	isk_trans_response.isat_np = isk_trans.isat_np;
	isk_trans_response.isat_reserved = isk_trans.isat_reserved;
	length = ((total_length) - sizeof(isk_hdr) - sizeof(isk_sa) - sizeof(isk_prop));
	isk_trans_response.isat_length = length;
	isk_trans_response.isat_transnum = isk_trans.isat_transnum;
	isk_trans_response.isat_transid = isk_trans.isat_transid;
	isk_trans_response.isat_reserved2 = isk_trans.isat_reserved2;
	
    encodeIsakmpTransform(MM_R1_response_packet,&isk_trans_response);

	//Encode ISAKMP Attributes
	STAILQ_FOREACH(n, &head, pointers) {
	
		encodeIsakmpAttribute(MM_R1_response_packet,&(n->isk_att));
		
     //  printf("PRINT IKE ATTRIBUTE LIST-1 %04X \n",n->isk_att.isaat_af_type);
      //  printf("PRINT IKE ATTRIBUTE LIST-2 %04X \n",n->isk_att.isaat_lv);
      }
	
	//printf("TOTAL LENGTH %d \n ", ntohl(total_length));
	//printPayload(MM_R1_response_packet->data, MM_R1_response_packet->size);	
	//MM_R1_response_packet[(total_length)+1];
	// SET ISAKMP PEER INFO STATE TO NEXT STATE
	node_t->state = MM_R2;
	
	printf("Print response \n");
	printPayload(MM_R1_response_packet->data, MM_R1_response_packet->size);	
	printf("\n");
	return MM_R1_response_packet;


}

struct packet *MM_R2_state(struct packet *p,struct isakmp_hdr isk_hdr){
/*
	struct isakmp_nonce isk_nonce;
	struct isakmp_key_exchange isk_keyex;
	
	unsigned int next_payload;
	next_payload = isk_hdr.isa_np;
		// THIS CODE MUST BE IN A DISTINCT FUNCTION FOR MM_R1
	while(next_payload!=0){
	
		switch(next_payload){

			case KE:
				memcpy((unsigned char*)&isk_keyex.isk_hdr_generic,data+(sizeof(struct isakmp_hdr)),sizeof(struct isakmp_generic_payload));
				isk_keyex.isakey_data = (unsigned char *) malloc(ntohs(isk_keyex.isk_hdr_generic.isagen_length) - (sizeof(struct isakmp_generic_payload)));
				
				memcpy((unsigned char*)isk_keyex.isakey_data,data+(sizeof(struct isakmp_hdr))+(sizeof(struct isakmp_generic_payload)), ntohs(isk_keyex.isk_hdr_generic.isagen_length) - (sizeof(struct isakmp_generic_payload)));
				printf("\n");
				printf("KE :\n");
				printPayload(isk_keyex.isakey_data, ntohs(isk_keyex.isk_hdr_generic.isagen_length) - (sizeof(struct isakmp_generic_payload)));
				//
				next_payload = ntohs(isk_keyex.isk_hdr_generic.isagen_np);
				state = MM_R2;
			case NONCE:
				memcpy((unsigned char*)&isk_nonce.isk_hdr_generic,data+(sizeof(struct isakmp_hdr))+ntohs(isk_keyex.isk_hdr_generic.isagen_length),sizeof(struct isakmp_generic_payload));
				isk_nonce.isan_data = (unsigned char *) malloc(ntohs(isk_nonce.isk_hdr_generic.isagen_length) - (sizeof(struct isakmp_generic_payload)));
				
				memcpy((unsigned char*)isk_nonce.isan_data,data+(sizeof(struct isakmp_hdr))+ntohs(isk_keyex.isk_hdr_generic.isagen_length)+sizeof(struct isakmp_generic_payload), ntohs(isk_nonce.isk_hdr_generic.isagen_length) - (sizeof(struct isakmp_generic_payload)));
				//memcpy((unsigned char*)&isk_sa,data+(sizeof(isk_hdr)),sizeof(isk_sa));
				printf("DEBUG NONCE LENGTH %04X\n", ntohs(isk_nonce.isk_hdr_generic.isagen_length));
				//isk_nonce
				printf("NONCE \n");
				printPayload(isk_nonce.isan_data, ntohs(isk_nonce.isk_hdr_generic.isagen_length) - (sizeof(struct isakmp_generic_payload)));
				//next_payload = ntohs(isk_nonce.isk_hdr_generic.isagen_np);
				next_payload = 0;
			break;


		}		


	}
*/

printf("initialize MM_R2_state \n");

return NULL;
}




struct packet* processPacket(struct packet *p, u_int16_t size){
	
	struct isakmp_peer_info *node;
	struct isakmp_hdr isk_hdr = {0};
	struct packet *result;
	
	//memcpy((unsigned char*)&isk_hdr,data,sizeof(isk_hdr));	// Still need to validate ISKMP header
	decodeIsakmpHeader(p,&isk_hdr);

	STAILQ_FOREACH(node, &peer_head, pointers) {

			if(strncmp(node->CKY_I,isk_hdr.isa_icookie,8) == 0 && strncmp(node->CKY_R,isk_hdr.isa_rcookie,8) == 0 ){
				// IF EXIST SEND TO RIGHT STATE
			
				switch(node->state){

					
					case MM_R2:
						printf("MM_R2\n");
						result = MM_R2_state(p,isk_hdr);
						return result;
					
					break;
					
					case MM_R3:
					
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

        //printf("PRINT IKE ATTRIBUTE LIST %04X \n",htons(n->isk_att.isaat_lv));
     }

		//if initiator or responder TODO		
	struct isakmp_peer_info *newPeer =  malloc(sizeof(struct isakmp_peer_info));
	memcpy(newPeer->CKY_I,isk_hdr.isa_icookie,8);
	memcpy(newPeer->CKY_R,isk_hdr.isa_rcookie,8);
	
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
	printf("test\n");
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

        // print details of the client/peer and the data received
        
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
//	printPayload(result,sizeof(result));
	//memset(buf,0,BUFLEN);
	
        // now reply the client with the same data
        //if (sendto(s, buf, recv_len, 0, (struct sockaddr*) &si_other, slen) == -1)
       // {
        //    die("sendto()");
        //}
    }

    close(s);
	
	
	

	}



int main(void)
{
	printf("start\n");
	startIpsec();
    return 0;
}
