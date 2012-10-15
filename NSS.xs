#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdio.h>
#include <string.h>

#if defined(XP_UNIX)
#include <unistd.h>
#endif

// #include "prerror.h"

#include "pk11func.h"
#include "seccomon.h"
// #include "secutil.h"
#include "secmod.h"
#include "secitem.h"
#include "cert.h"
#include "ocsp.h"


/* #include <stdlib.h> */
/* #include <errno.h> */
/* #include <fcntl.h> */
/* #include <stdarg.h> */

#include "nspr.h"
#include "plgetopt.h"
#include "prio.h"
#include "nss.h"

/* #include "vfyutil.h" */

#define RD_BUF_SIZE (60 * 1024)


/* fake our package name */
//typedef NSS*  Crypt__NSS;
typedef CERTCertificate* Crypt__NSS__Certificate;

// Make a scalar ref to a class object
/* static SV* sv_make_ref(const char* class, void* object) {
  SV* rv;

  rv = newSV(0);
  sv_setref_pv(rv, class, (void*) object);

  if (! sv_isa(rv, class) ) {
    croak("Error creating reference to %s", class);
  }

  return rv;
} */

#define REVCONFIG_TEST_UNDEFINED      0
#define REVCONFIG_TEST_LEAF           1
#define REVCONFIG_TEST_CHAIN          2
#define REVCONFIG_METHOD_CRL          1
#define REVCONFIG_METHOD_OCSP         2

#define REV_METHOD_INDEX_MAX  4

typedef struct RevMethodsStruct {
    uint testType;
    char *testTypeStr;
    uint testFlags;
    char *testFlagsStr;
    uint methodType;
    char *methodTypeStr;
    uint methodFlags;
    char *methodFlagsStr;
} RevMethods;

RevMethods revMethodsData[REV_METHOD_INDEX_MAX];


SECStatus
configureRevocationParams(CERTRevocationFlags *flags)
{
   int i;
   uint testType = REVCONFIG_TEST_UNDEFINED;
   static CERTRevocationTests *revTests = NULL;
   PRUint64 *revFlags;

   for(i = 0;i < REV_METHOD_INDEX_MAX;i++) {
       if (revMethodsData[i].testType == REVCONFIG_TEST_UNDEFINED) {
           continue;
       }
       if (revMethodsData[i].testType != testType) {
           testType = revMethodsData[i].testType;
           if (testType == REVCONFIG_TEST_CHAIN) {
               revTests = &flags->chainTests;
           } else {
               revTests = &flags->leafTests;
           }
           revTests->number_of_preferred_methods = 0;
           revTests->preferred_methods = 0;
           revFlags = revTests->cert_rev_flags_per_method;
       }
       /* Set the number of the methods independently to the max number of
        * methods. If method flags are not set it will be ignored due to
        * default DO_NOT_USE flag. */
       revTests->number_of_defined_methods = cert_revocation_method_count;
       revTests->cert_rev_method_independent_flags |=
           revMethodsData[i].testFlags;
       if (revMethodsData[i].methodType == REVCONFIG_METHOD_CRL) {
           revFlags[cert_revocation_method_crl] =
               revMethodsData[i].methodFlags;
       } else if (revMethodsData[i].methodType == REVCONFIG_METHOD_OCSP) {
           revFlags[cert_revocation_method_ocsp] =
               revMethodsData[i].methodFlags;
       }
   }
   return SECSuccess;
}

SECStatus sv_to_item(SV* certSv, SECItem* dst) {
  STRLEN len;
  char *cert;

  cert = SvPV(certSv, len);

  if ( len <= 0 ) {
    return SECFailure;
  }

  dst->len = 0;
  dst->data = NULL;

  dst->data = (unsigned char*)PORT_Alloc(len);
  PORT_Memcpy(dst->data, cert, len);
  dst->len = len;

  return SECSuccess;
}

SV* item_to_sv(SECItem* item) {
  return newSVpvn((const char*) item->data, item->len);
}

MODULE = Crypt::NSS    PACKAGE = Crypt::NSS

PROTOTYPES: DISABLE

BOOT:
{
  //HV *stash = gv_stashpvn("Crypt::OpenSSL::X509", 20, TRUE);

  /* struct { char *n; I32 v; } Crypt__OpenSSL__X509__const[] = {

  {"OPENSSL_VERSION_NUMBER", OPENSSL_VERSION_NUMBER},
  {"FORMAT_UNDEF", FORMAT_UNDEF},
  {"FORMAT_ASN1", FORMAT_ASN1},
  {"FORMAT_TEXT", FORMAT_TEXT},
  {"FORMAT_PEM", FORMAT_PEM},
  {"FORMAT_NETSCAPE", FORMAT_NETSCAPE},
  {"FORMAT_PKCS12", FORMAT_PKCS12},
  {"FORMAT_SMIME", FORMAT_SMIME},
  {"FORMAT_ENGINE", FORMAT_ENGINE},
  {"FORMAT_IISSGC", FORMAT_IISSGC},
  {"V_ASN1_PRINTABLESTRING",  V_ASN1_PRINTABLESTRING},
  {"V_ASN1_UTF8STRING",  V_ASN1_UTF8STRING},
  {"V_ASN1_IA5STRING",  V_ASN1_IA5STRING},
  {Nullch,0}}; */
  
  SECStatus            secStatus;

  PR_Init( PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

  secStatus = NSS_NoDB_Init(NULL);
  //SECMOD_AddNewModule("Builtins", DLL_PREFIX"nssckbi."DLL_SUFFIX, 0, 0);

  if (secStatus != SECSuccess) {
    croak("NSS init");
  }

  //SECU_RegisterDynamicOids();
}

SV*
add_cert_to_db(cert)
  Crypt::NSS::Certificate cert;

  PREINIT:
    PK11SlotInfo *slot = NULL;
    CERTCertTrust *trust = NULL;
  CERTCertDBHandle *defaultDB;
    SECStatus rv;

  CODE:
    RETVAL = 0;

  defaultDB = CERT_GetDefaultCertDB();

  slot = PK11_GetInternalKeySlot();
  trust = (CERTCertTrust *)PORT_ZAlloc(sizeof(CERTCertTrust));
  if (!trust) {
    croak("Could not create trust");
  }

    rv = CERT_DecodeTrustString(trust, "c");
    if (rv) {
croak("unable to decode trust string");
}

	rv =  PK11_ImportCert(slot, cert, CK_INVALID_HANDLE, "test", PR_FALSE);
	if (rv != SECSuccess) {
croak("Could not add cert to db");
}

    rv = CERT_ChangeCertTrust(defaultDB, cert, trust);
    if (rv != SECSuccess) {
croak("Could not change cert trust");
}

    PORT_Free(trust);

    RETVAL = newSViv(1);   
  

  OUTPUT: 
  RETVAL

MODULE = Crypt::NSS    PACKAGE = Crypt::NSS::Certificate

SV*
accessor(cert)
  Crypt::NSS::Certificate cert  

  ALIAS:
  subject = 1
  issuer = 2  
  serial = 3
  version = 8

  PREINIT:

  CODE:

  if ( ix == 1 ) {
    RETVAL = newSVpvf("%s", cert->subjectName);
  } else if ( ix == 2 ) {
    RETVAL = newSVpvf("%s", cert->issuerName);
  } else if ( ix == 3 ) {
    RETVAL = item_to_sv(&cert->serialNumber);
  } else if ( ix == 8 ) {
    RETVAL = item_to_sv(&cert->version);
  } else {
    croak("Unknown accessor %d", ix);
  }


  OUTPUT:
  RETVAL

SV*
verify(cert)
  Crypt::NSS::Certificate cert;

  PREINIT:
//  PRTime time = 0;
//  CERTCertDBHandle *defaultDB;
  SECStatus secStatus;
  PRBool certFetching = PR_FALSE; // automatically get AIA certs

  static CERTValOutParam cvout[4];
  static CERTValInParam cvin[6];
  int inParamIndex = 0;
  static CERTRevocationFlags rev;
  static PRUint64 revFlagsLeaf[2];
  static PRUint64 revFlagsChain[2];

  CODE:


  cvin[inParamIndex].type = cert_pi_useAIACertFetch;
  cvin[inParamIndex].value.scalar.b = certFetching;
  inParamIndex++;
  
  rev.leafTests.cert_rev_flags_per_method = revFlagsLeaf;
  rev.chainTests.cert_rev_flags_per_method = revFlagsChain;
  secStatus = configureRevocationParams(&rev);
 
  if (secStatus) {
    croak("Can not configure revocation parameters");
  }

  cvin[inParamIndex].type = cert_pi_end;
  
  cvout[0].type = cert_po_trustAnchor;
  cvout[0].value.pointer.cert = NULL;
  cvout[1].type = cert_po_certList;
  cvout[1].value.pointer.chain = NULL;

  secStatus = CERT_PKIXVerifyCert(cert, certUsageSSLServer,
                                  cvin, cvout, NULL);
  

  if (secStatus != SECSuccess ) {
    RETVAL = newSViv(0);
  } else {
    RETVAL = newSViv(1);
  }  

  OUTPUT: 
  RETVAL

Crypt::NSS::Certificate
new(class, string)
  SV  *string

  PREINIT:
  CERTCertificate *cert;
  CERTCertDBHandle *defaultDB;
  //PRFileDesc*     fd;
  SECStatus       rv;
  SECItem         item        = {0, NULL, 0};

  CODE:
 // SV  *class

  defaultDB = CERT_GetDefaultCertDB();
  rv = sv_to_item(string, &item);
  if (rv != SECSuccess) {
    croak("sv_to_item failed");
  }

  cert = CERT_NewTempCertificate(defaultDB, &item, 
                                   NULL     /* nickname */, 
                                   PR_FALSE /* isPerm */, 
				   PR_TRUE  /* copyDER */);

  
  if (!cert) {
    PRErrorCode err = PR_GetError();
    croak( "couldn't import certificate %d = %s\n",
	         err, PORT_ErrorToString(err));
    PORT_Free(item.data);
  }

  RETVAL = cert;

  OUTPUT:
  RETVAL


