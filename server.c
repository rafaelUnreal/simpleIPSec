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
//Identification (ID)            5


// IKEv1 states
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

// ISAKMP HEADER

struct isakmp_hdr
{
    u_int8_t    isa_icookie[8];
    u_int8_t    isa_rcookie[8];
    u_int8_t    isa_np;                 /* Next payload */
    u_int8_t	isa_version;	/* high-order 4 bits: Major; low order 4: Minor */
    u_int8_t    isa_xchg;		/* Exchange type */
    u_int8_t    isa_flags;
    u_int32_t   isa_msgid;		/* Message ID (RAW) */
    u_int32_t   isa_length;		/* Length of message */
};

struct isakmp_sa
{
    u_int8_t  isasa_np;			/* Next payload */
    u_int8_t  isasa_reserved;
    u_int16_t isasa_length;		/* Payload length */
    u_int32_t isasa_doi;		/* DOI */
    u_int32_t isasa_situation;		/* situation */
 
};

struct isakmp_proposal
{
    u_int8_t    isap_np;
    u_int8_t    isap_reserved;
    u_int16_t   isap_length;
    u_int8_t    isap_proposal;
    u_int8_t    isap_protoid;
    u_int8_t    isap_spisize;
    u_int8_t    isap_notrans;		/* Number of transforms */
};

struct isakmp_transform
{
    u_int8_t    isat_np;
    u_int8_t    isat_reserved;
    u_int16_t   isat_length;
    u_int8_t    isat_transnum;		/* Number of the transform */
    u_int8_t    isat_transid;
    u_int16_t   isat_reserved2;
};

struct isakmp_generic_payload 
{
    u_int8_t    isagen_np;
    u_int8_t    isagen_reserved;
    u_int16_t   isagen_length;


};

struct isakmp_nonce
{
	struct isakmp_generic_payload isk_hdr_generic;
    unsigned char *   isan_data;
};


struct isakmp_key_exchange
{
    struct isakmp_generic_payload isk_hdr_generic;
    unsigned char *   isakey_data;
};




// class                         value              type


// class                         value              type

// class                         value              type
// -------------------------------------------------------------------
// Encryption Algorithm                1                 B
// Hash Algorithm                      2                 B
// Authentication Method               3                 B
// Group Description                   4                 B
// Group Type                          5                 B
// Group Prime/Irreducible Polynomial  6                 V
// Group Generator One                 7                 V
// Group Generator Two                 8                 V
// Group Curve A                       9                 V
// Group Curve B                      10                 V
// Life Type                          11                 B
// Life Duration                      12                 V
// PRF                                13                 B
// Key Length                         14                 B
// Field Size                         15                 B
// Group Order                        16                 V

struct isakmp_attribute
{
    /* The high order bit of isaat_af_type is the Attribute Format
 *      * If it is off, the format is TLV: lv is the length of the following
 *           * attribute value.
 *                * If it is on, the format is TV: lv is the value of the attribute.
 *                     * ISAKMP_ATTR_AF_MASK is the mask in host form.
 *                          *
 *                               * The low order 15 bits of isaat_af_type is the Attribute Type.
 *                                    * ISAKMP_ATTR_RTYPE_MASK is the mask in host form.
 *                                         */
    u_int16_t isaat_af_type;   /* high order bit: AF; lower 15: rtype */
    u_int16_t isaat_lv;			/* Length or value */
};

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

// die prints the error message on stderr and exits with a non-success code
void die(char *s)
{
    perror(s);
    exit(1);
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


unsigned char * MM_R1_state(struct isakmp_hdr isk_hdr, struct isakmp_sa isk_sa, struct isakmp_proposal isk_prop, struct isakmp_transform isk_trans){


	struct isakmp_attribute_node *n;
	
	unsigned char * MM_R1_response_packet;
	
	u_int32_t  total_length = 0;
	u_int16_t  ike_att_length = 0;
	u_int16_t  length;
	u_int32_t htonlvar;
	u_int16_t  htonsvar;
	//Responding with same IKE attributes and calculating length for transform length
	//
	STAILQ_FOREACH(n, &head, pointers) {
	ike_att_length = ike_att_length + (sizeof(struct isakmp_attribute));
        //printf("PRINT IKE ATTRIBUTE LIST %04X \n",htons(n->isk_att.isaat_af_type));
        //printf("PRINT IKE ATTRIBUTE LIST %04X \n",htons(n->isk_att.isaat_lv));
        }
	//printf("IKE_ATT LENGTH %d \n ", ike_att_length);
	//n = NULL;
	
	//Calculator HDR ISK total length
	
	total_length = htonl(sizeof(struct isakmp_hdr) + sizeof(struct isakmp_sa) + sizeof(struct isakmp_proposal) + sizeof(struct isakmp_transform) + ike_att_length); 
	
	//printf("ALL IKE ATTRIBUTE SIZE %d\n", ike_att_length);
	//printf("Total length %04X\n", total_length);;
	//        printf("hex id: %08lX \n",htonl(isk_hdr.isa_length));
        //printf("size: %04X \n",sizeof(isk_hdr.isa_length));
        //printf("size: %04X \n",sizeof(isk_hdr.isa_length));
        //printf("ISAKMP SA: NEXT PAYLOAD: %02X \n",isk_sa.isasa_np);
       // printf("ISAKMP SA: PAYLOAD LENGHT: %04X \n",htons(isk_sa.isasa_length));
       // printf("ISAKMP PROPOSAL SA: NEXT PAYLOAD: %02X \n",isk_prop.isap_np);
       // printf("ISAKMP PROPOSAL SA: PAYLOAD LENGHT: %04X \n",htons(isk_prop.isap_length));
        //printf("ISAKMP TRANSFORM: NEXT PAYLOAD: %02X \n",isk_trans.isat_np);


	MM_R1_response_packet = (unsigned char *)malloc(total_length+1);

	memcpy(MM_R1_response_packet, &(isk_hdr.isa_icookie), 8);
	memcpy(MM_R1_response_packet+8, "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
	memcpy(MM_R1_response_packet+16, &(isk_hdr.isa_np), 1);
	memcpy(MM_R1_response_packet+17, &(isk_hdr.isa_version), 1);
	memcpy(MM_R1_response_packet+18, &(isk_hdr.isa_xchg), 1);
	memcpy(MM_R1_response_packet+19, &(isk_hdr.isa_flags), 1);
	memcpy(MM_R1_response_packet+20, &(isk_hdr.isa_msgid), 4);
	memcpy(MM_R1_response_packet+24, &total_length, 4);
	//MM_R1_response_packet[29] = '\0';
	 //printf("TEST: %X \n",htonl(MM_R1_response_packet[19]));

	printf("\n");
	memcpy(MM_R1_response_packet+28, "\x0", 1);
	memcpy(MM_R1_response_packet+29, &(isk_sa.isasa_reserved), 1);
	length = htons(ntohl(total_length) - sizeof(isk_hdr));
	memcpy(MM_R1_response_packet+30, &length, 2);
	memcpy(MM_R1_response_packet+32, &isk_sa.isasa_doi, 4);
	memcpy(MM_R1_response_packet+36, &isk_sa.isasa_situation, 4);



	memcpy(MM_R1_response_packet+40, &(isk_prop.isap_np), 1);
	memcpy(MM_R1_response_packet+41, &(isk_prop.isap_reserved), 1);
	length = htons(ntohl(total_length) - sizeof(isk_hdr) - sizeof(isk_sa));
	memcpy(MM_R1_response_packet+42, &length, 2);
	memcpy(MM_R1_response_packet+44, &(isk_prop.isap_proposal), 1);
	memcpy(MM_R1_response_packet+45, &(isk_prop.isap_protoid), 1);
	memcpy(MM_R1_response_packet+46, &(isk_prop.isap_spisize), 1);
	memcpy(MM_R1_response_packet+47, "\x1", 1);

	

	memcpy(MM_R1_response_packet+48, "\x0", 1);
	memcpy(MM_R1_response_packet+49, &(isk_trans.isat_reserved), 1 );

	length = htons(ntohl(total_length) - sizeof(isk_hdr) - sizeof(isk_sa) - sizeof(isk_prop));

	memcpy(MM_R1_response_packet+50, &length, 2);
	memcpy(MM_R1_response_packet+52, &(isk_trans.isat_transnum), 1);
	memcpy(MM_R1_response_packet+53, &(isk_trans.isat_transid), 1);
	memcpy(MM_R1_response_packet+54, &(isk_trans.isat_reserved2),2);



	unsigned int fixed_payload = 54;

	STAILQ_FOREACH(n, &head, pointers) {
		fixed_payload = fixed_payload + 2;
		htonsvar = n->isk_att.isaat_af_type;
		memcpy(MM_R1_response_packet+fixed_payload, &htonsvar ,2);
		fixed_payload = fixed_payload + 2;
		htonsvar = n->isk_att.isaat_lv;
		memcpy(MM_R1_response_packet+fixed_payload, &htonsvar, 2);
		
       // printf("PRINT IKE ATTRIBUTE LIST-1 %04X \n",n->isk_att.isaat_af_type);
        //printf("PRINT IKE ATTRIBUTE LIST-2 %04X \n",n->isk_att.isaat_lv);
        }

	//printf("TOTAL LENGTH %d \n ", ntohl(total_length));
	//printPayload(MM_R1_response_packet, ntohl(total_length));	
	MM_R1_response_packet[ntohl(total_length)+1];

	
	return MM_R1_response_packet;


}

unsigned char * MM_R2_state(){



printf("initialize MM_R2_state \n");


}




unsigned char * processPacket(unsigned char *data, int size){

	struct isakmp_hdr isk_hdr;
	struct isakmp_sa isk_sa;
	struct isakmp_proposal isk_prop;
	struct isakmp_transform isk_trans;
	struct isakmp_attribute isk_att;
	struct isakmp_attribute_node *isk_attp;
	struct isakmp_generic_payload isk_generic;
	struct isakmp_nonce isk_nonce;
	struct isakmp_key_exchange isk_keyex;

	unsigned int next_payload; // ISAKMP header has to have at least 1 SA
	unsigned int position=0;
	unsigned int next_prop_payload;
	unsigned int next_trans_payload;
	unsigned int numAtt;
	//INITIALIZE HEAD OF LIST
	STAILQ_INIT(&head); 
		
	memcpy((unsigned char*)&isk_hdr,data,sizeof(isk_hdr));	// Still need to valida ISKMP header
	next_payload = isk_hdr.isa_np;
	position = sizeof(isk_hdr);

	// THIS CODE MUST BE IN A DISTINCT FUNCTION FOR MM_R1
	while(next_payload!=0){
	
		switch(next_payload){

			case SA_ID:
				memcpy((unsigned char*)&isk_sa,data+(sizeof(isk_hdr)),sizeof(isk_sa));	
				next_payload = isk_sa.isasa_np;
				
				memcpy((unsigned char*)&isk_prop,(data+(sizeof(isk_hdr)+sizeof(isk_sa))),sizeof(isk_prop));	


				//TODO LOOP THROUGH ALL PROPOSALS
				next_prop_payload = isk_prop.isap_np;	
				
				memcpy((unsigned char*)&isk_trans,(data+(sizeof(isk_hdr)+sizeof(isk_sa)+sizeof(isk_prop))),sizeof(isk_trans));
				//TODO LOOP THROUGH ALL TRANSFORMS
				next_trans_payload = isk_trans.isat_np;
				

				//LOOP THROUGH ALL IKE ATTRIBUTES
				numAtt = 0;
				//printf("size of trans %X",sizeof(isk_trans));
				//printf("size of trans lenght %d", htons(isk_trans.isat_length));
				//unsigned int result =  htons(isk_trans.isat_length) - 8;
				
				//printf("result %d", result);
				while(numAtt < (htons(isk_trans.isat_length) - sizeof(isk_trans)) ){

						
					isk_attp = malloc(sizeof(struct isakmp_attribute_node));      /* Insert at the head. */
					memcpy((unsigned char*)&isk_attp->isk_att,(data+(sizeof(isk_hdr)+sizeof(isk_sa)+sizeof(isk_prop)+sizeof(isk_trans)+numAtt)),sizeof(isk_att));
					STAILQ_INSERT_TAIL(&head, isk_attp, pointers);

					numAtt+=4; // Size of basic IKE attribute

				}; 
				state = MM_R1;
				next_payload = 0;
	
			break;

			case KE:
				memcpy((unsigned char*)&isk_keyex.isk_hdr_generic,data+(sizeof(struct isakmp_hdr)),sizeof(struct isakmp_generic_payload));
				isk_keyex.isakey_data = (unsigned char *) malloc(ntohs(isk_keyex.isk_hdr_generic.isagen_length) - (sizeof(struct isakmp_generic_payload)));
				
				memcpy((unsigned char*)isk_keyex.isakey_data,data+(sizeof(struct isakmp_hdr))+(sizeof(struct isakmp_generic_payload)), ntohs(isk_keyex.isk_hdr_generic.isagen_length) - (sizeof(struct isakmp_generic_payload)));
				printf("\n");
				//printf("DEBUG KEY EXCHANGE LENGTH %04X\n", ntohs(isk_keyex.isk_hdr_generic.isagen_length) - (sizeof(struct isakmp_generic_payload)));
				
				//printf("\n");
				//printf("DEBUG KEY EXCHANGE LENGTH %04X\n", isk_keyex.isk_hdr_generic.isagen_length);
				
				//printf("\n");
				//printf("DEBUG KEY EXCHANGE LENGTH %04X\n", sizeof(struct isakmp_generic_payload));
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
	//Copy generic ISAKMP header to struct first 28 bytes


	// Loop through payloads // 
	
	//TeST
	struct isakmp_attribute_node *n;
	//printf("Size of ISK_HDR: %d\n",sizeof(isk_hdr));
	//printf("\n");
	//printPayload(isk_hdr.isa_icookie,8);
	//printPayload(isk_hdr.isa_rcookie,8);
	//printf("\n");
	//printf("hex id: %08lX \n",htonl(isk_hdr.isa_length));
	//printf("size: %04X \n",sizeof(isk_hdr.isa_length));
	//printf("size: %04X \n",sizeof(isk_hdr.isa_length));
	//printf("ISAKMP SA: NEXT PAYLOAD: %02X \n",isk_sa.isasa_np);
	//printf("ISAKMP SA: PAYLOAD LENGHT: %04X \n",htons(isk_sa.isasa_length));
	//printf("ISAKMP PROPOSAL SA: NEXT PAYLOAD: %02X \n",isk_prop.isap_np);
	//printf("ISAKMP PROPOSAL SA: PAYLOAD LENGHT: %04X \n",htons(isk_prop.isap_length));
	//printf("ISAKMP TRANSFORM: NEXT PAYLOAD: %02X \n",isk_trans.isat_np);
	//SLIST_FOREACH(n, &head, pointers) {
	
	//printf("PRINT IKE ATTRIBUTE LIST %04X \n",n->isk_att.isaat_af_type); 
       // }
	if (state == MM_R1) {
		return MM_R1_state(isk_hdr, isk_sa, isk_prop, isk_trans);
		
	}
	else if (state == MM_R2) {
			printf("MM_R2 :D\n");
			return NULL;
		
	}
	
	
	
	// END OF MM_R1 FUNCTION
}

//bool mainMode_inI1(struct isakmp_hdr){

//}



int main(void)
{
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
    unsigned char buf[BUFLEN];

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
	unsigned char * result = processPacket(buf,recv_len);
	
	if(result!=NULL){

	   if (sendto(s, result, 84, 0, (struct sockaddr*) &si_other, slen) == -1)
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
    return 0;
}
