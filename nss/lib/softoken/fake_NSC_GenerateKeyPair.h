#ifndef __fake_NSC_GenerateKeyPair__h
#define __fake_NSC_GenerateKeyPair__h

#include "../util/pkcs11t.h"
#include "../util/seccomon.h"

CK_RV
fake_NSC_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                    CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                    CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
                    CK_OBJECT_HANDLE_PTR phPrivateKey, SECItem * key_share_xtn, PRBool is_MB);
#endif
