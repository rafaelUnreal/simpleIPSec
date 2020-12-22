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
	
	if (config_lookup_int64(cf, "ike.main_mode.mm_responder_1.responder_spi", &enabled)){
		printf("Enabled: %s\n", enabled ? "Yep" : "Nope");
		printf("Responder SPI %lld \n",enabled);
	}

	return 0;
	
}

int getNumPayloads(){
	
	config_setting_t *setting;
	setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
	if(setting != NULL){
		int count = config_setting_length(setting);

		return count;
	}
	else{ return 0; }
	 
}

int getPayloadType(int payloadElem){

	if(payloadElem == 0){
		
		config_setting_t *setting;
		int isa_np;
		config_setting_t *payload_setting;
		config_setting_t *payload_elem;
		setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1");
			if(config_setting_lookup_int(setting, "next_payload", &isa_np)){
				return isa_np;
			}
	}
	//Else need to check previous payload
	else if(payloadElem <= getNumPayloads()){
		
		config_setting_t *setting;
		int isa_np;
		setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
		config_setting_t *payload_elem = config_setting_get_elem(setting, payloadElem-1);
			if(config_setting_lookup_int(payload_elem, "next_payload", &isa_np)){
				return isa_np;
				} 	
	}
}

int getNumProposals(int payloadElem){
	
	config_setting_t *setting;
	setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
	
	if(setting != NULL){
			config_setting_t *payload_elem = config_setting_get_elem(setting, payloadElem);
			config_setting_t *proposal_settings = config_setting_get_member(payload_elem, "proposal");
			if(proposal_settings==NULL){return 0;}
			int count = config_setting_length(proposal_settings);

			return count;
	}
	else{ return 0; }
	
	
}

int getNumTransforms(int payloadElem, int proposalElem){
	
	config_setting_t *setting;
	setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
	
	if(setting != NULL){
			//get payload element settings
			config_setting_t *payload_elem = config_setting_get_elem(setting, payloadElem);
			config_setting_t *proposal_settings = config_setting_get_member(payload_elem, "proposal");
			config_setting_t *proposal_elem = config_setting_get_elem(proposal_settings, proposalElem);
			config_setting_t *transform_settings = config_setting_get_member(proposal_elem, "transform");

			if(transform_settings==NULL){return 0;}
			int count = config_setting_length(transform_settings);
			return count;
	}
	else{ return 0; }
	
	
}

int getNumIkeAttributes(int payloadElem, int proposalElem, int transFormElem){
	
	config_setting_t *setting;
	setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
	
	if(setting != NULL){
			//get payload element settings
			config_setting_t *payload_elem = config_setting_get_elem(setting, payloadElem);
			config_setting_t *proposal_settings = config_setting_get_member(payload_elem, "proposal");
			config_setting_t *proposal_elem = config_setting_get_elem(proposal_settings, proposalElem);
			config_setting_t *transform_settings = config_setting_get_member(proposal_elem, "transform");
			config_setting_t *transform_elem = config_setting_get_elem(transform_settings, transFormElem);
			config_setting_t *ike_settings = config_setting_get_member(transform_elem, "ike_attribute");
			
			if(ike_settings==NULL){return 0;}
			int count = config_setting_length(ike_settings);
			//printf("\n");
			//printf("num of ike attributes %d\n",count);
			return count;
	}
	else{ return 0; }
}



void configSetSecurityAssociationResponseMM1(config_setting_t *sa_payload, struct isakmp_sa *isakmp_sa_mm1, struct isakmp_sa defaultValue){
	
	int _isasa_np;			
    int _isasa_reserved;
    int _isasa_length;		
    int _isasa_doi;		
    int _isasa_situation;		
	int _isasa_situation_identity;
	int _isasa_situation_integrity;
	int _isasa_situation_secrecry;
	config_setting_t *situation;

	
	if (config_setting_lookup_int(sa_payload, "next_payload", &_isasa_np)){
		isakmp_sa_mm1->isasa_np = _isasa_np;
	}
	if (config_setting_lookup_int(sa_payload, "reserved", &_isasa_reserved)){
		isakmp_sa_mm1->isasa_reserved = _isasa_reserved;
	}
	if (config_setting_lookup_int(sa_payload, "payload_length", &_isasa_length)){
		isakmp_sa_mm1->isasa_length = _isasa_length;
	}
	if (config_setting_lookup_int(sa_payload, "domain_of_interpretation", &_isasa_doi)){
		isakmp_sa_mm1->isasa_doi = _isasa_doi;
	}
	situation = config_setting_get_member(sa_payload, "situation");
	if (config_setting_lookup_int(situation, "identity", &_isasa_situation_identity)){
		(isakmp_sa_mm1->isasa_situation) |= (_isasa_situation_identity & 0x01);
	}
	if (config_setting_lookup_int(situation, "secrecry", &_isasa_situation_secrecry)){
		(isakmp_sa_mm1->isasa_situation) |= ((_isasa_situation_secrecry << 1) & 0x02);
	}
	if (config_setting_lookup_int(situation, "integrity", &_isasa_situation_integrity)){
		(isakmp_sa_mm1->isasa_situation) |= ((_isasa_situation_integrity << 2) & 0x04);
	}
	

}



void configSetProposalResponseMM1(int payloadElem, int proposalElem, struct isakmp_proposal *isakmp_prop_sa_mm1, struct isakmp_proposal defaultValue) {
	
	int _isap_np;
    int _isap_reserved;
    int _isap_length;
    int _isap_proposal;
    int _isap_protoid;
    int _isap_spisize;
    int _isap_notrans;
	
	config_setting_t *setting;
	setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
	
	if(setting != NULL){
			//get payload element settings
			config_setting_t *payload_elem = config_setting_get_elem(setting, payloadElem);
			config_setting_t *proposal_settings = config_setting_get_member(payload_elem, "proposal");
			config_setting_t *proposal_elem = config_setting_get_elem(proposal_settings, proposalElem);
		
			if(proposal_elem==NULL){return;}
			
				if (config_setting_lookup_int(proposal_elem, "next_payload", &_isap_np)){
					isakmp_prop_sa_mm1->isap_np = _isap_np;
				}
				if (config_setting_lookup_int(proposal_elem, "reserved", &_isap_reserved)){
					isakmp_prop_sa_mm1->isap_reserved = _isap_reserved;
				}
				if (config_setting_lookup_int(proposal_elem, "length", &_isap_length)){
					isakmp_prop_sa_mm1->isap_length = _isap_length;
				}
				if (config_setting_lookup_int(proposal_elem, "proposal_number", &_isap_proposal)){
					isakmp_prop_sa_mm1->isap_proposal = _isap_proposal;
				}
				if (config_setting_lookup_int(proposal_elem, "protocol_id", &_isap_protoid)){
					isakmp_prop_sa_mm1->isap_protoid = _isap_protoid;
				}
				if (config_setting_lookup_int(proposal_elem, "spi_size", &_isap_spisize)){
					isakmp_prop_sa_mm1->isap_spisize = _isap_spisize;
				}
				if (config_setting_lookup_int(proposal_elem, "proposal_transform", &_isap_notrans)){
					isakmp_prop_sa_mm1->isap_notrans = _isap_notrans;
				}
			
	
			
	}
	
}



void configSetTransformResponseMM1(int payloadElem, int proposalElem, int transformElem, struct isakmp_transform *isakmp_trans_sa_mm1, struct isakmp_transform defaultValue) {
	
	int   _isat_np;
    int   _isat_reserved;
    int   _isat_length;
    int   _isat_transnum;		
    int   _isat_transid;
    int   _isat_reserved2;
	
	config_setting_t *setting;
	setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
	
	if(setting != NULL){
			//get payload element settings
			config_setting_t *payload_elem = config_setting_get_elem(setting, payloadElem);
			config_setting_t *proposal_settings = config_setting_get_member(payload_elem, "proposal");
			config_setting_t *proposal_elem = config_setting_get_elem(proposal_settings, proposalElem);
			config_setting_t *transform_settings = config_setting_get_member(proposal_elem, "transform");
			config_setting_t *transform_elem = config_setting_get_elem(transform_settings, transformElem);

			if(transform_elem==NULL){return ;}
			
				if (config_setting_lookup_int(transform_elem, "next_payload", &_isat_np)){
					isakmp_trans_sa_mm1->isat_np = _isat_np;
				}		
				if (config_setting_lookup_int(transform_elem, "reserverd", &_isat_reserved)){
					isakmp_trans_sa_mm1->isat_reserved = _isat_reserved;
				}
				if (config_setting_lookup_int(transform_elem, "length", &_isat_length)){
					isakmp_trans_sa_mm1->isat_length = _isat_length;
				}
				if (config_setting_lookup_int(transform_elem, "transform_number", &_isat_transnum)){
					isakmp_trans_sa_mm1->isat_transnum = _isat_transnum;
				}
				if (config_setting_lookup_int(transform_elem, "transform_id", &_isat_transid)){
					isakmp_trans_sa_mm1->isat_transid = _isat_transid;
				}
				if (config_setting_lookup_int(transform_elem, "reserved2", &_isat_reserved2)){
					isakmp_trans_sa_mm1->isat_reserved2 = _isat_reserved2;
				}
	}
}

void configSetIkeResponseMM1(int payloadElem, int proposalElem, int transformElem, int ikeElem, struct isakmp_attribute *isakmp_ike_attrib_mm1){
	
	int _isaat_af_type;  
    int _isaat_lv;	
	
	
		config_setting_t *setting;
	setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
	
	if(setting != NULL){
			//get payload element settings
			config_setting_t *payload_elem = config_setting_get_elem(setting, payloadElem);
			config_setting_t *proposal_settings = config_setting_get_member(payload_elem, "proposal");
			config_setting_t *proposal_elem = config_setting_get_elem(proposal_settings, proposalElem);
			config_setting_t *transform_settings = config_setting_get_member(proposal_elem, "transform");
			config_setting_t *transform_elem = config_setting_get_elem(transform_settings, transformElem);
			config_setting_t *ike_settings = config_setting_get_member(transform_elem, "ike_attribute");
			config_setting_t *ike_elem = config_setting_get_elem(ike_settings, ikeElem);

			if(ike_elem==NULL){return ;}
			
				if (config_setting_lookup_int(ike_elem, "type", &_isaat_af_type)){
					isakmp_ike_attrib_mm1->isaat_af_type = _isaat_af_type;
				}		
				if (config_setting_lookup_int(ike_elem, "value", &_isaat_lv)){
					isakmp_ike_attrib_mm1->isaat_lv = _isaat_lv;
				}
	}
	
	
	
}




int configSetPayloadHdrResponseMM1(int payloadElem, struct isakmp_sa *isakmp_sa_mm1, struct isakmp_sa defaultValue){
	
	//First payload type verification is on ISAKMP header
	//First payload is always security association, just for fun I am allowing anything.
	if(payloadElem == 0){
		
		config_setting_t *setting;
		int isa_np;
		config_setting_t *payload_setting;
		config_setting_t *payload_elem;
		setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1");
			if(config_setting_lookup_int(setting, "next_payload", &isa_np)){
				
				switch(isa_np){
					
				case SA_ID:

					payload_setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
					payload_elem = config_setting_get_elem(payload_setting, payloadElem);
					printf("payload of security association\n");
					configSetSecurityAssociationResponseMM1(payload_elem,isakmp_sa_mm1,defaultValue);
					
				default:
					printf("something else \n");
					
				}
			}
	}
	//Else need to check previous payload
	else if(payloadElem <= getNumPayloads()){
		
		config_setting_t *setting;
		int isa_np;
		setting = config_lookup(&cfg, "ike.main_mode.mm_responder_1.payload");
		config_setting_t *payload_elem = config_setting_get_elem(setting, payloadElem-1);
			if(config_setting_lookup_int(payload_elem, "next_payload", &isa_np)){
				
				switch(isa_np){
					
				case SA_ID:
					printf("payload of security association\n");
				
				case VENDOR_ID:
					printf("vendor ID payload \n");
				default:
					printf("something else \n");
					
				}
		}
		 
		
	}
	
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