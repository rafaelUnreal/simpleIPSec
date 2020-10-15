#ifndef DH_H
#define DH_H

//Study Point 2
/*
Include guards usage and can avoid issues with a header in multiple places with multiple declarations.
However, a header CAN be used in multiple compiling units
*/


//Study point 1 - Why header prototype is important and leads to such warning
//assignment makes pointer from integer without a cast [enabled by default]
/*
The problem here is a missing prototype. For historical reasons C lets
you use functions without declaring them. However, all such functions 
are considered returning int, and all their parameters are considered int as well.
*/
unsigned char * calculateSharedSecret(unsigned char *pubKey, int * secret_size);
unsigned char *calculateHmacSha1(unsigned char *key, int key_len, unsigned char *data,int  data_len);
unsigned char *calculateSHA1(unsigned char *data, unsigned int len);

















#endif