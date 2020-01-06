#ifndef ENCODE_H
#define ENCODE_H
#include "packet.h"
void encodeIsakmpHeader(struct packet *p, struct isakmp_hdr *isa);
void decodeIsakmpHeader(struct packet *p, struct isakmp_hdr *isa);

#endif