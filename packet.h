#include <stdlib.h>
#ifndef PACKET_H
#define PACKET_H

// Default parameters for isakmp attributes
#define	AES_CBC_128	1
#define	SHA_1	2
#define PRE_SHARED_KEY	3
#define DH2	4
#define ISAKMP_HDR_SIZE	28


// OFFSETS:

#define ISAKMP_HDR_OFFSET	0
#define SA_OFFSET	28
#define PROPOSAL_OFFSET	40
#define TRANSFORM_OFFSET	48
#define ATTRIBUTE_OFFSET	56

// Generic Buffer Packet Struct
struct packet 
{
	unsigned char * data;
	u_int16_t index;
	u_int16_t data_size;
	u_int16_t size;

};


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

//void setIsakmpIcookie(struct isakmp_hdr *hdr, unsigned char *str);
//void setIsakmpRcookie(struct isakmp_hdr *hdr, unsigned char *str);
//void setIsakmpNp(struct isakmp_hdr *hdr, u_int8_t np);
//void setIsakmpMajorVersion(struct isakmp_hdr * hdr, u_int8_t version);
//void setIsakmpMinorVersion(struct isakmp_hdr * hdr, u_int8_t version);
//void setIsakmpFlagEncryption(struct isakmp_hdr * hdr, bool enable);
//void setIsakmpFlagAuthentication(struct isakmp_hdr * hdr, bool enable);
//void setIsakmpFlagCommit(struct isakmp_hdr * hdr, bool enable);
	
	

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
    unsigned char *isan_data;
};


struct isakmp_key_exchange
{
    struct isakmp_generic_payload isk_hdr_generic;
    unsigned char *isakey_data;
};

struct _isakmp_ipsec_id
{
    u_int8_t    isaiid_np;
    u_int8_t    isaiid_reserved;
    u_int16_t   isaiid_length;
    u_int8_t    isaiid_idtype;
    u_int8_t    isaiid_protoid;
    u_int16_t   isaiid_port;
};

struct isakmp_ipsec_id
{
    struct _isakmp_ipsec_id isk_ipsec_id;
    unsigned char *id_data;
};



struct isakmp_hash
{
    struct isakmp_generic_payload isk_hdr_generic;
    unsigned char *hash_data;
};



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

#endif

