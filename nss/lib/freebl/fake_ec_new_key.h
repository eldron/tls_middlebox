#ifndef __fake_ec_new_key__h
#define __fake_ec_new_key__h

#include "blapit.h"
#include "../util/seccomon.h"
#include "../pk11wrap/secmodt.h"

extern SECStatus fake_EC_NewKey(ECParams *params,
                           ECPrivateKey **privKey, SECItem * key_share_xtn, PRBool is_MB);

#endif
