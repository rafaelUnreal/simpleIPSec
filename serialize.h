#ifndef SERIALIZE_H
#define SERIALIZE_H
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>



void packi16(unsigned char *buf, u_int16_t i);
void packi32(unsigned char *buf, u_int32_t i);
void packi64(unsigned char *buf, u_int64_t i);

u_int16_t unpacku16(unsigned char *buf);
u_int32_t unpacku32(unsigned char *buf);
u_int64_t unpacku64(unsigned char *buf);

#endif