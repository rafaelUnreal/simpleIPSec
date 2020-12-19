#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>


//libconfig documentation: https://hyperrealm.github.io/libconfig/libconfig_manual.html#Configuration-Files


int initConfig(){
	
	
	const config_setting_t *cf_setting;
	
	const char *base = NULL;
	int count, n;
	long long int enabled;
	
	cf = &cfg;
	config_init(cf);
	
	if (!config_read_file(cf, "simpleipsec.cfg")) {
		fprintf(stderr, "%s:%d - %s\n",
			config_error_file(cf),
			config_error_line(cf),
			config_error_text(cf));
		config_destroy(cf);
		return(EXIT_FAILURE);
	}

	//if (config_lookup_string(cf, "ike.main_mode.mm_responder_1.responder_spi", &base))
	//	printf("Host: %s\n", base);

	cf_setting = config_lookup(cf, "ldap.retries");
	//count = config_setting_length(cf_setting);
	
//	cf_setting =  config_setting_set_format(cf,"ike.main_mode.mm_responder_1.initiator_spi"
	
	if (config_lookup_int64(cf, "ike.main_mode.mm_responder_1.responder_spi", &enabled)){
		printf("Enabled: %s\n", enabled ? "Yep" : "Nope");
		printf("Responder SPI %lld \n",enabled);
	}
	//}
	//else {
	//	printf("Enabled is not defined\n");
	//}


	//printf("I have %d retries:\n", count);
	//for (n = 0; n < count; n++) {
	//	printf("\t#%d. %d\n", n + 1,
	//		config_setting_get_int_elem(cf_setting, n));
	//}

	//config_destroy(cf);
	return 0;
	
}

void configSetIsakmpHdrResponseMM1(struct isakmp_hdr *isakmp_mm1, struct isakmp_hdr defaultValue){
	
	long long int responder_spi;
    long long int initiator_spi;	
	int    isa_np;                 
    int	isa_majorVersion;
	int	isa_minorVersion;
	int    isa_xchg;		
	int    isa_flags_encryption;
	int    isa_flags_commit;
	int    isa_flags_authentication;
    int   isa_msgid;		
    int   isa_length;		
	
	if (config_lookup_int64(cf, "ike.main_mode.mm_responder_1.responder_spi", &responder_spi)){
		isakmp_mm1->isa_rcookie[0] = ( responder_spi >> 56) & 0xFF; isakmp_mm1->isa_rcookie[1] = ( responder_spi >> 48) & 0xFF;
		isakmp_mm1->isa_rcookie[2] = ( responder_spi >> 40) & 0xFF; isakmp_mm1->isa_rcookie[3] = ( responder_spi >> 32) & 0xFF;
		isakmp_mm1->isa_rcookie[4] = ( responder_spi >> 24) & 0xFF; isakmp_mm1->isa_rcookie[5] = ( responder_spi >> 16) & 0xFF;
		isakmp_mm1->isa_rcookie[6] = ( responder_spi >> 8) & 0xFF; isakmp_mm1->isa_rcookie[7] = responder_spi & 0xFF;
	} else{ memcpy( isakmp_mm1->isa_rcookie, defaultValue.isa_rcookie, sizeof(u_int8_t) * ISAKMP_COOKIE_SIZE);}
	
	if (config_lookup_int64(cf, "ike.main_mode.mm_responder_1.initiator_spi", &initiator_spi)){
		isakmp_mm1->isa_icookie[0] = ( initiator_spi >> 56) & 0xFF; isakmp_mm1->isa_icookie[1] = ( initiator_spi >> 48) & 0xFF;
		isakmp_mm1->isa_icookie[2] = ( initiator_spi >> 40) & 0xFF; isakmp_mm1->isa_icookie[3] = ( initiator_spi >> 32) & 0xFF;
		isakmp_mm1->isa_icookie[4] = ( initiator_spi >> 24) & 0xFF; isakmp_mm1->isa_icookie[5] = ( initiator_spi >> 16) & 0xFF;
		isakmp_mm1->isa_icookie[6] = ( initiator_spi >> 8) & 0xFF; isakmp_mm1->isa_icookie[7] =  initiator_spi & 0xFF;
	} else{ memcpy(isakmp_mm1->isa_icookie, defaultValue.isa_icookie, sizeof(u_int8_t) * ISAKMP_COOKIE_SIZE);}
	
	///
	if (config_lookup_int(cf, "ike.main_mode.mm_responder_1.next_payload", &isa_np)){
			isakmp_mm1->isa_np = isa_np;
	} else { isakmp_mm1->isa_np = defaultValue.isa_np;}
	
	if (config_lookup_int(cf, "ike.main_mode.mm_responder_1.version.majorVersion", &isa_majorVersion)){
			isakmp_mm1->isa_version |= ((isa_majorVersion << 4)& 0xF0);
	} 
	
	if (config_lookup_int(cf, "ike.main_mode.mm_responder_1.version.minorVersion", &isa_minorVersion)){
			isakmp_mm1->isa_version |= (isa_minorVersion & 0x0F);
	} 
	
	if (config_lookup_int(cf, "ike.main_mode.mm_responder_1.exchange_type", &isa_xchg)){
			isakmp_mm1->isa_xchg = isa_xchg;
	} 
	if (config_lookup_int(cf, "ike.main_mode.mm_responder_1.flags.encryption", &isa_flags_encryption)){
			isakmp_mm1->isa_flags |= (isa_flags_encryption & 0x01);
	}
	if (config_lookup_int(cf, "ike.main_mode.mm_responder_1.flags.commit", &isa_flags_commit)){
			isakmp_mm1->isa_flags |= ((isa_flags_commit << 1) & 0x02);
	}
	if (config_lookup_int(cf, "ike.main_mode.mm_responder_1.flags.authentication", &isa_flags_authentication)){
			isakmp_mm1->isa_flags |= ((isa_flags_authentication << 2)& 0x04);	
	}
	if (config_lookup_int(cf, "ike.main_mode.mm_responder_1.message_id", &isa_msgid)){
			isakmp_mm1->isa_msgid = isa_msgid;	
	}
	if (config_lookup_int(cf, "ike.main_mode.mm_responder_1.message_id", &isa_length)){
			isakmp_mm1->isa_length = isa_length;	
	}
	
	

	

}