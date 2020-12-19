#include <stdlib.h>
#ifndef CONFIG_H
#define CONFIG_H

#include <libconfig.h>
#include "packet.h"

int parseConfig();

void configSetIsakmpHdrResponseMM1(struct isakmp_hdr *isakmp_mm1, struct isakmp_hdr defaultValue);

config_t cfg,*cf;


#endif