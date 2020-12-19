#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include "encode.h"
#include "packet.h"
#include "serialize.h"

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

enum enconding_type {
	
	U_INT_8 = 8,
	U_INT_16 = 16,
	U_INT_32 = 32,
	U_INT_64 = 64,
	SPI,
	CHUNK_DATA, //Variable size
	PAYLOAD_LIST
};

struct enconding_rule {
	
	enum enconding_type type;
	u_int32_t offset;
	
};


static struct enconding_rule encoding_isakmp_header[] = {
	/* 8 Byte SPI, stored in the field initiator_spi */
	{ SPI,		offsetof(struct isakmp_hdr, isa_icookie)	},
	/* 8 Byte SPI, stored in the field responder_spi */
	{ SPI,		offsetof(struct isakmp_hdr, isa_rcookie)	},
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,		offsetof(struct isakmp_hdr, isa_np)	},
	/* 4 Bit major version, stored in the field maj_version */ /* 4 Bit minor version, stored in the field min_version */
	{ U_INT_8,		offsetof(struct isakmp_hdr, isa_version)		},
	{ U_INT_8,		offsetof(struct isakmp_hdr, isa_xchg)		},
	/* 8 Bit for the exchange type */
	{ U_INT_8,		offsetof(struct isakmp_hdr, isa_flags)	},
	/* 4 Byte message id, stored in the field message_id */
	{ U_INT_32,			offsetof(struct isakmp_hdr, isa_msgid)	},
	/* 4 Byte length field, stored in the field length */
	{ U_INT_32,		offsetof(struct isakmp_hdr, isa_length)	 }
};


static struct enconding_rule encoding_isakmp_sa[] = {
	
	{ U_INT_8,		offsetof(struct isakmp_sa, isasa_np)	},
	{ U_INT_8,		offsetof(struct isakmp_sa, isasa_reserved)	},
	{ U_INT_16,		offsetof(struct isakmp_sa, isasa_length)	},
	{ U_INT_32,		offsetof(struct isakmp_sa, isasa_doi)		},
	{ U_INT_32,		offsetof(struct isakmp_sa, isasa_situation)		}

};


static struct enconding_rule encoding_isakmp_proposal[] = {
	
	{ U_INT_8,		offsetof(struct isakmp_proposal, isap_np)	},
	{ U_INT_8,		offsetof(struct isakmp_proposal, isap_reserved)	},
	{ U_INT_16,		offsetof(struct isakmp_proposal, isap_length)	},
	{ U_INT_8,		offsetof(struct isakmp_proposal, isap_proposal)		},
	{ U_INT_8,		offsetof(struct isakmp_proposal, isap_protoid)		},
	{ U_INT_8,		offsetof(struct isakmp_proposal, isap_spisize)	},
	{ U_INT_8,		offsetof(struct isakmp_proposal, isap_notrans)	}

};


static struct enconding_rule encoding_isakmp_id[] = {
	
	{ U_INT_8,		offsetof(struct _isakmp_ipsec_id, isaiid_np)	},
	{ U_INT_8,		offsetof(struct _isakmp_ipsec_id, isaiid_reserved)	},
	{ U_INT_16,		offsetof(struct _isakmp_ipsec_id, isaiid_length)	},
	{ U_INT_8,		offsetof(struct _isakmp_ipsec_id, isaiid_idtype)		},
	{ U_INT_8,		offsetof(struct _isakmp_ipsec_id, isaiid_protoid)		},
	{ U_INT_16,		offsetof(struct _isakmp_ipsec_id, isaiid_port)	}


};

static struct enconding_rule encoding_isakmp_transform[] = {
	
	{ U_INT_8,		offsetof(struct isakmp_transform, isat_np)	},
	{ U_INT_8,		offsetof(struct isakmp_transform, isat_reserved)	},
	{ U_INT_16,		offsetof(struct isakmp_transform, isat_length)	},
	{ U_INT_8,		offsetof(struct isakmp_transform, isat_transnum)		},
	{ U_INT_8,		offsetof(struct isakmp_transform, isat_transid)		},
	{ U_INT_16,		offsetof(struct isakmp_transform, isat_reserved2)	}
};

static struct enconding_rule encoding_isakmp_attribute[] = {
	
	{ U_INT_16,	offsetof(struct isakmp_attribute, isaat_af_type)},
	{ U_INT_16,	offsetof(struct isakmp_attribute, isaat_lv)	},

};


static struct enconding_rule encoding_isakmp_generic[] = {
	
	{ U_INT_8,		offsetof(struct isakmp_generic_payload, isagen_np)	},
	{ U_INT_8,		offsetof(struct isakmp_generic_payload, isagen_reserved)	},
	{ U_INT_16,		offsetof(struct isakmp_generic_payload, isagen_length)	},

};


void encodeFields(struct packet *p, int field, u_int32_t offset, void *s ){
	
	unsigned char *byteArray = (unsigned char *) s;
	int i;
	switch(field){
		
	
	case U_INT_8:
		p->data[p->index] = byteArray[offset];
		p->index = p->index + 1;
		p->data_size = p->data_size + 1;
	
	break;
	
	case U_INT_16:
		//printf("pdata0 ENCODE: %02X\n" , byteArray[offset]	);
		//printf("pdata1 ENCODE: %02X\n" ,byteArray[offset+1]);
	
		packi16( &(p->data[p->index]), *(u_int16_t *)&byteArray[offset]);
		//printf("pdata0 ENCODE 2: %02X\n" , p->data[p->index]	);
		//printf("pdata1 ENCODE 2: %02X\n" ,p->data [p->index+1]);
		p->index = p->index + 2;

		p->data_size = p->data_size + 2;
	break;
	case U_INT_32:
	
		//printf(" " BYTE_TO_BINARY_PATTERN,  BYTE_TO_BINARY(byteArray[offset]));
		//printf(" " BYTE_TO_BINARY_PATTERN,   BYTE_TO_BINARY(byteArray[offset+1]));
		//printf(" " BYTE_TO_BINARY_PATTERN,  BYTE_TO_BINARY(byteArray[offset+2]));
		//printf(" " BYTE_TO_BINARY_PATTERN,  BYTE_TO_BINARY(byteArray[offset+3]));
		//printf("\n");
	
	//printf( " ALL BYTES %d \n", *(u_int32_t *)&byteArray[offset]);
		packi32( &(p->data[p->index]), *(u_int32_t *)&byteArray[offset]);
		p->index = p->index + 4;
		p->data_size = p->data_size + 4;
	break;
	
	case U_INT_64:
	
	//printf(" " BYTE_TO_BINARY_PATTERN,  BYTE_TO_BINARY(byteArray[offset]));
	//printf(" " BYTE_TO_BINARY_PATTERN,  BYTE_TO_BINARY(byteArray[offset+1]));
	//printf(" " BYTE_TO_BINARY_PATTERN,  BYTE_TO_BINARY(byteArray[offset+2]));
	//printf(" " BYTE_TO_BINARY_PATTERN,  BYTE_TO_BINARY(byteArray[offset+3]));
	//printf("\n");
	
	//printf( " ALL BYTES %d \n", *(u_int32_t *)&byteArray[offset]);
		packi64( &(p->data[p->index]), *(u_int64_t *)&byteArray[offset]);
		p->index = p->index + 8;
		p->data_size = p->data_size + 8;
	
	break;
	
	case SPI:
		for(i =0; i<8; i++){
			p->data[p->index+i] =  byteArray[offset+i];
		}
		p->index = p->index + 8;
		p->data_size = p->data_size + 8;
	break;
		
	}	
}

void encodeIsakmpHeader(struct packet *p, struct isakmp_hdr *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_header) / sizeof(encoding_isakmp_header[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encodings[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		encodeFields(p,encoding_isakmp_header[i].type, encoding_isakmp_header[i].offset, isa);
		
	}	
}
void encodeIsakmpGeneric(struct packet *p, struct isakmp_generic_payload *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_generic) / sizeof(encoding_isakmp_generic[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encodings[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		encodeFields(p,encoding_isakmp_generic[i].type, encoding_isakmp_generic[i].offset, isa);
		
	}	
}


void encodeIsakmpProposal(struct packet *p, struct isakmp_proposal *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_proposal) / sizeof(encoding_isakmp_proposal[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encodings[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		encodeFields(p,encoding_isakmp_proposal[i].type, encoding_isakmp_proposal[i].offset, isa);
		
	}	
}

void encodeIsakmpSa(struct packet *p, struct isakmp_sa *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_sa) / sizeof(encoding_isakmp_sa[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encodings[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		encodeFields(p,encoding_isakmp_sa[i].type, encoding_isakmp_sa[i].offset, isa);
		
	}	
}

void encodeIsakmpTransform(struct packet *p, struct isakmp_transform *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_transform) / sizeof(encoding_isakmp_transform[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encoding_isakmp_transform[i].offset);
		//printf("isa length: %d \n", isa->isat_length);
		encodeFields(p,encoding_isakmp_transform[i].type, encoding_isakmp_transform[i].offset, isa);
		
	}	
}

void encodeIsakmpAttribute(struct packet *p, struct isakmp_attribute *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_attribute) / sizeof(encoding_isakmp_attribute[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encodings[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		encodeFields(p,encoding_isakmp_attribute[i].type, encoding_isakmp_attribute[i].offset, isa);
		
	}	
}


void encodeIsakmpId(struct packet *p, struct _isakmp_ipsec_id *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_id) / sizeof(encoding_isakmp_id[0]); 
	
	for(i=0; i < size; i++){

		encodeFields(p,encoding_isakmp_id[i].type, encoding_isakmp_id[i].offset, isa);
		
	}	
}



void encodeChunk(struct packet *p, unsigned char *chunkData, u_int16_t size)
{
		memcpy(&(p->data[p->index]), chunkData , size);
		p->index = p->index + size;		
		p->data_size = p->data_size + size;
}


void decodeFields(struct packet *p, int field, u_int32_t offset, void *s ){
	
	unsigned char *byteArray = (unsigned char *) s;
	int i;
	switch(field){
		
	case U_INT_8:
		byteArray[offset] = p->data[p->index];
		p->index = p->index + 1;
		//p->size = p->size + 1;
	
	break;
	
	case U_INT_16:
		*(u_int16_t *)(s+offset) = unpacku16(&(p->data[p->index]));
		//memcpy(byteArray[offset], unpacku16(&(p->data[p->index])),2);
		//printf("CASE %02X\n", unpacku16(&(p->data[p->index])));
		p->index = p->index + 2;
		//printf(" " BYTE_TO_BINARY_PATTERN,  BYTE_TO_BINARY(byteArray[offset]));
		//printf(" " BYTE_TO_BINARY_PATTERN,   BYTE_TO_BINARY(byteArray[offset+1]));
		//p->size = p->size + 2;
	break;
	case U_INT_32:
	

		*(u_int32_t *)(s+offset) = unpacku32(&(p->data[p->index]));
		p->index = p->index + 4;
		//p->size = p->size + 4;
	break;
	
	case U_INT_64:
	
		*(u_int64_t *)(s+offset)  = unpacku64(&(p->data[p->index]));
		p->index = p->index + 8;
		//p->size = p->size + 8;
	
	break;
	
	case SPI:
		//unsigned int *x;
		//x =  (unsigned int*) 
		for(i =0; i<8; i++){
			byteArray[offset+i] =  p->data[p->index+i];
		}
		p->index = p->index + 8;
		break;
		
	}	
}


void decodeIsakmpHeader(struct packet *p, struct isakmp_hdr *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_header) / sizeof(encoding_isakmp_header[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encodings[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		decodeFields(p,encoding_isakmp_header[i].type, encoding_isakmp_header[i].offset, isa);
		
	}	
}


void decodeIsakmpSa(struct packet *p, struct isakmp_sa *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_sa) / sizeof(encoding_isakmp_sa[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encodings[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		decodeFields(p,encoding_isakmp_sa[i].type, encoding_isakmp_sa[i].offset, isa);
		
	}	
}

void decodeIsakmpProposal(struct packet *p, struct isakmp_proposal *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_proposal) / sizeof(encoding_isakmp_proposal[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encodings[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		decodeFields(p,encoding_isakmp_proposal[i].type, encoding_isakmp_proposal[i].offset, isa);
		
	}	
}

void decodeIsakmpGeneric(struct packet *p, struct isakmp_generic_payload *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_generic) / sizeof(encoding_isakmp_generic[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encodings[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		decodeFields(p,encoding_isakmp_generic[i].type, encoding_isakmp_generic[i].offset, isa);
		
	}	
}

void decodeChunk(struct packet *p, unsigned char *chunkData, u_int16_t size)
{
		memcpy(chunkData, &(p->data[p->index]), size);
		p->index = p->index + size;		

}




void decodeIsakmpTransform(struct packet *p, struct isakmp_transform *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_transform) / sizeof(encoding_isakmp_transform[0]); 
	
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,  encoding_isakmp_transform[i].offset);
		//printf("isa length: %d \n", isa->isat_length);
		decodeFields(p,encoding_isakmp_transform[i].type, encoding_isakmp_transform[i].offset, isa);
		
	}	
}

void decodeIsakmpAttribute(struct packet *p, struct isakmp_attribute *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_attribute) / sizeof(encoding_isakmp_attribute[0]); 
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,   encoding_isakmp_attribute[i].offset);
		//printf("isa length: %d \n", isa->isa_length);
		decodeFields(p,encoding_isakmp_attribute[i].type, encoding_isakmp_attribute[i].offset, isa);
		
	}	
}

void decodeIsakmpId(struct packet *p, struct _isakmp_ipsec_id *isa)
{
	u_int16_t size;
	u_int16_t i;
	size = sizeof(encoding_isakmp_id) / sizeof(encoding_isakmp_id[0]); 
	for(i=0; i < size; i++){
		//printf("offset of %d \n" ,   encoding_isakmp_id[i].offset);
		//printf("isa length: %d \n", isa->isaiid_length);
		decodeFields(p,encoding_isakmp_id[i].type, encoding_isakmp_id[i].offset, isa);
		
	}	
}


