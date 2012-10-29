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
#include "secmod.h"
#include "secitem.h"
#include "secder.h"
#include "secerr.h"
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


#define NS_ASSERTION(expr, str)    \
do { \
  if ( !(expr)) { \
   croak("NS_ASSERTION triggered: %s", str); \
  } \
} while(0)


/* From SSLServerCertVerification */

// Call this if we have already decided that a cert should be treated as INVALID,
// in order to check if we to worsen the error to REVOKED.
PRErrorCode
PSM_SSL_DigiNotarTreatAsRevoked(CERTCertificate * serverCert,
                                CERTCertList * serverCertChain)
{
  // If any involved cert was issued by DigiNotar, 
  // and serverCert was issued after 01-JUL-2011,
  // then worsen the error to revoked.
  
  PRTime cutoff = 0;
  PRStatus status = PR_ParseTimeString("01-JUL-2011 00:00", true, &cutoff);
  if (status != PR_SUCCESS) {
    NS_ASSERTION(status == PR_SUCCESS, "PR_ParseTimeString failed");
    // be safe, assume it's afterwards, keep going
  } else {
    PRTime notBefore = 0, notAfter = 0;
    if (CERT_GetCertTimes(serverCert, &notBefore, &notAfter) == SECSuccess &&
           notBefore < cutoff) {
      // no worsening for certs issued before the cutoff date
      return 0;
    }
  }
  
  for (CERTCertListNode *node = CERT_LIST_HEAD(serverCertChain);
       !CERT_LIST_END(node, serverCertChain);
       node = CERT_LIST_NEXT(node)) {
    if (node->cert->issuerName &&
        strstr(node->cert->issuerName, "CN=DigiNotar")) {
      return SEC_ERROR_REVOKED_CERTIFICATE;
    }
  }
  
  return 0;
}


// Call this only if a cert has been reported by NSS as VALID
PRErrorCode
PSM_SSL_BlacklistDigiNotar(CERTCertificate * serverCert,
                           CERTCertList * serverCertChain)
{
  bool isDigiNotarIssuedCert = false;

  for (CERTCertListNode *node = CERT_LIST_HEAD(serverCertChain);
       !CERT_LIST_END(node, serverCertChain);
       node = CERT_LIST_NEXT(node)) {
    if (!node->cert->issuerName)
      continue;

    if (strstr(node->cert->issuerName, "CN=DigiNotar")) {
      isDigiNotarIssuedCert = true;
    }
  }

  if (isDigiNotarIssuedCert) {
    // let's see if we want to worsen the error code to revoked.
    PRErrorCode revoked_code = PSM_SSL_DigiNotarTreatAsRevoked(serverCert, serverCertChain);
    return (revoked_code != 0) ? revoked_code : SEC_ERROR_UNTRUSTED_ISSUER;
  }

  return 0;
}

struct nsSerialBinaryBlacklistEntry
{
  unsigned int len;
  const char *binary_serial;
};

// bug 642395
static struct nsSerialBinaryBlacklistEntry myUTNBlacklistEntries[] = {
  { 17, "\x00\x92\x39\xd5\x34\x8f\x40\xd1\x69\x5a\x74\x54\x70\xe1\xf2\x3f\x43" },
  { 17, "\x00\xd8\xf3\x5f\x4e\xb7\x87\x2b\x2d\xab\x06\x92\xe3\x15\x38\x2f\xb0" },
  { 16, "\x72\x03\x21\x05\xc5\x0c\x08\x57\x3d\x8e\xa5\x30\x4e\xfe\xe8\xb0" },
  { 17, "\x00\xb0\xb7\x13\x3e\xd0\x96\xf9\xb5\x6f\xae\x91\xc8\x74\xbd\x3a\xc0" },
  { 16, "\x39\x2a\x43\x4f\x0e\x07\xdf\x1f\x8a\xa3\x05\xde\x34\xe0\xc2\x29" },
  { 16, "\x3e\x75\xce\xd4\x6b\x69\x30\x21\x21\x88\x30\xae\x86\xa8\x2a\x71" },
  { 17, "\x00\xe9\x02\x8b\x95\x78\xe4\x15\xdc\x1a\x71\x0a\x2b\x88\x15\x44\x47" },
  { 17, "\x00\xd7\x55\x8f\xda\xf5\xf1\x10\x5b\xb2\x13\x28\x2b\x70\x77\x29\xa3" },
  { 16, "\x04\x7e\xcb\xe9\xfc\xa5\x5f\x7b\xd0\x9e\xae\x36\xe1\x0c\xae\x1e" },
  { 17, "\x00\xf5\xc8\x6a\xf3\x61\x62\xf1\x3a\x64\xf5\x4f\x6d\xc9\x58\x7c\x06" },
  { 0, 0 } // end marker
};


// --- end SSLServerCertVerification


/* fake our package name */
typedef CERTCertificate* NSS__Certificate;
typedef CERTCertList* NSS__CertList;

char* initstring;


//---- Beginning here this is a direct copy from NSS vfychain.c

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
   PRUint64 *revFlags = NULL;

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

//---- end direct copy from vfychain.c

PRInt64 cert_usage_to_certificate_usage(enum SECCertUsageEnum usage) {
  switch(usage) {
    case certUsageSSLClient:
      return certificateUsageSSLClient;
    case certUsageSSLServer:
      return certificateUsageSSLServer;
    case certUsageSSLServerWithStepUp:
      return certificateUsageSSLServerWithStepUp;
    case certUsageSSLCA:
      return certificateUsageSSLCA;
    case certUsageEmailSigner:
      return certificateUsageEmailSigner;
    case certUsageEmailRecipient:
      return certificateUsageEmailRecipient;
    case certUsageObjectSigner:
      return certificateUsageObjectSigner;
    case certUsageUserCertImport:
      return certificateUsageUserCertImport;
    case certUsageVerifyCA:
      return certificateUsageVerifyCA;
    case certUsageProtectedObjectSigner:
      return certificateUsageProtectedObjectSigner;
    case certUsageStatusResponder:
      return certificateUsageStatusResponder;
    case certUsageAnyCA:
      return certificateUsageAnyCA;
    default:
      croak("Unknown certificate usage %d", usage);
  }
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

MODULE = NSS    PACKAGE = NSS

PROTOTYPES: DISABLE

BOOT:
{
  HV *stash = gv_stashpvn("NSS", 3, TRUE);

  struct { char *n; I32 s; } NSS__const[] = {

  {"certUsageSSLClient", certUsageSSLClient},
  {"certUsageSSLServer", certUsageSSLServer},
  {"certUsageSSLServerWithStepUp", certUsageSSLServerWithStepUp},
  {"certUsageSSLCA", certUsageSSLCA},
  {"certUsageEmailSigner", certUsageEmailSigner},
  {"certUsageEmailRecipient", certUsageEmailRecipient},
  {"certUsageObjectSigner", certUsageObjectSigner},
  {"certUsageUserCertImport", certUsageUserCertImport},
  {"certUsageVerifyCA", certUsageVerifyCA},
  {"certUsageProtectedObjectSigner", certUsageProtectedObjectSigner},
  {"certUsageStatusResponder",  certUsageStatusResponder},
  {"certUsageAnyCA",  certUsageAnyCA},
  {Nullch,0}
  };

  char *name;
  int i;

  for (i = 0; (name = NSS__const[i].n); i++) {
    newCONSTSUB(stash, name, newSViv(NSS__const[i].s));
  }

  
  PR_Init( PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

  //SECU_RegisterDynamicOids();
}

void
_init_nodb()

  PREINIT:
  SECStatus secStatus;
  //PRUint32 initFlags;
  
  CODE:
  //initFlags = NSS_INIT_NOCERTDB | NSS_INIT_NOMODDB | NSS_INIT_NOROOTINIT;
  
  //secStatus = NSS_Initialize("test2", "", "", SECMOD_DB, initFlags);
  secStatus = NSS_NoDB_Init(NULL);
  initstring = NULL;
  //SECMOD_AddNewModule("Builtins", DLL_PREFIX"nssckbi."DLL_SUFFIX, 0, 0);

  if (secStatus != SECSuccess) {
    croak("NSS init");
  }

  
void
_init_db(string)
  SV* string;

  PREINIT:
  SECStatus secStatus;
  char* path;
  STRLEN pathlen;

  CODE:
  path = SvPV(string, pathlen);

  secStatus = NSS_InitReadWrite(path);
  initstring = (char*) malloc(pathlen+1);
  bzero(initstring, pathlen+1);
  memcpy(initstring, path, pathlen);
  
  //SECMOD_AddNewModule("Builtins", DLL_PREFIX"nssckbi."DLL_SUFFIX, 0, 0);

  if (secStatus != SECSuccess) {
    PRErrorCode err = PR_GetError();
    croak("NSS Init failed: %d = %s\n",
                 err, PORT_ErrorToString(err));
  }


void 
__cleanup(void)
  
  PREINIT:
  SECStatus rv;
  
  CODE:
  rv = NSS_Shutdown();

  if (rv != SECSuccess) {
    PRErrorCode err = PR_GetError();
    croak( "NSS Shutdown failed %d = %s\n",
	         err, PORT_ErrorToString(err));
  }
  //printf("Destroy was happy\n");
  

SV*
add_cert_to_db(cert, string)
  NSS::Certificate cert;
  SV* string;

  ALIAS:
  add_trusted_cert_to_db = 1

  PREINIT:
  PK11SlotInfo *slot = NULL;
  CERTCertTrust *trust = NULL;
  CERTCertDBHandle *defaultDB;
  SECStatus rv;
  char* nick;

  CODE:
  RETVAL = 0;
  nick = SvPV_nolen(string);

  defaultDB = CERT_GetDefaultCertDB();

  slot = PK11_GetInternalKeySlot();

  if ( ix == 1 ) {
    // trusted Certificate
  
    trust = (CERTCertTrust *)PORT_ZAlloc(sizeof(CERTCertTrust));
    if (!trust) {
      croak("Could not create trust");
    }
  
    rv = CERT_DecodeTrustString(trust, "TCu,Cu,Tu"); // take THAT trust ;)
    if (rv) {
      croak("unable to decode trust string");
    }
  }
  
  rv = PK11_ImportCert(slot, cert, CK_INVALID_HANDLE, nick, PR_FALSE);
  if (rv != SECSuccess) {
    PRErrorCode err = PR_GetError();
    croak( "could not add certificate to db %d = %s\n",
	         err, PORT_ErrorToString(err));
  }

  if ( ix == 1 ) {
    rv = CERT_ChangeCertTrust(defaultDB, cert, trust);
    if (rv != SECSuccess) {
      croak("Could not change cert trust");
    }
  }

  PORT_Free(trust); 

  PK11_FreeSlot(slot);

  RETVAL = newSViv(1);   

  OUTPUT: 
  RETVAL


void
_reinit()

  PREINIT:
  SECStatus rv;

  CODE:

  rv = NSS_Shutdown();

  if (rv != SECSuccess) {
    PRErrorCode err = PR_GetError();
    croak( "NSS Shutdown failed during reinit. Last error-code: %d = %s\n", err, PORT_ErrorToString(err));
  }


  if ( initstring == NULL ) {
    rv = NSS_NoDB_Init(NULL);   
  } else {
    //printf("%s\n\n", initstring);
    rv = NSS_InitReadWrite(initstring);
  }
    
  if (rv != SECSuccess) {
    PRErrorCode err = PR_GetError();
    croak("NSS Init failed: %d = %s\n",                  
    err, PORT_ErrorToString(err));
  } 
    
  

void
dump_certificate_cache_info()

  CODE:
  nss_DumpCertificateCacheInfo();
  

MODULE = NSS    PACKAGE = NSS::CertList

NSS::CertList
new(class)

  PREINIT:
  CERTCertList *certList;

  CODE:
  certList = CERT_NewCertList();

  RETVAL = certList;

  OUTPUT:
  RETVAL

void
add(certlist, cert)
  NSS::CertList certlist;
  NSS::Certificate cert;

  CODE:
  CERTCertificate* addcert = CERT_DupCertificate(cert);
  CERT_AddCertToListTail(certlist, addcert);


void 
DESTROY(certlist)
  NSS::CertList certlist;

  PPCODE:

  if ( certlist ) {
    CERT_DestroyCertList(certlist); // memory leak - certificates in list are not actually deleted. 
    certlist = 0;
  }


MODULE = NSS    PACKAGE = NSS::Certificate

SV*
accessor(cert)
  NSS::Certificate cert  

  ALIAS:
  subject = 1
  issuer = 2  
  serial_raw = 3
  notBefore = 5
  notAfter = 6
  version = 8
  subj_alt_name = 9

  PREINIT:

  CODE:

  if ( ix == 1 ) {
    RETVAL = newSVpvf("%s", cert->subjectName);
  } else if ( ix == 2 ) {
    RETVAL = newSVpvf("%s", cert->issuerName);
  } else if ( ix == 3 ) {
    RETVAL = item_to_sv(&cert->serialNumber);
  } else if ( ix == 5 || ix == 6 ) {
    int64 time;
    SECStatus rv;
    char *timeString;
    PRExplodedTime printableTime; 

    if ( ix == 5 ) 
    	rv = DER_UTCTimeToTime(&time, &cert->validity.notBefore);
    else if ( ix == 6 )    
	rv = DER_UTCTimeToTime(&time, &cert->validity.notAfter);
    else
        croak("not possible");

    if (rv != SECSuccess)
      croak("Could not parse time");

    PR_ExplodeTime(time, PR_GMTParameters, &printableTime);
    timeString = PORT_Alloc(256);
    if ( ! PR_FormatTime(timeString, 256, "%a %b %d %H:%M:%S %Y", &printableTime) ) {
      croak("Could not format time string");
    }

    RETVAL = newSVpvf("%s", timeString);
    PORT_Free(timeString);
  } else if ( ix == 8 ) {
    // if version is not specified it it 1 (0).
    int version = cert->version.len ? DER_GetInteger(&cert->version) : 0;
    RETVAL = newSViv(version+1);
  } else if ( ix == 9 ) {
    SECStatus rv;
    SECItem           subAltName;
    CERTGeneralName * nameList;
    CERTGeneralName * current;
    PRArenaPool *     arena          = NULL;
    SV* out = newSVpvn("", 0);
    
    rv = CERT_FindCertExtension(cert, SEC_OID_X509_SUBJECT_ALT_NAME, 
      	&subAltName);

    if (rv != SECSuccess) {
    	//printf("No alt name!\n");
        RETVAL = &PL_sv_no;
        return;
    } 
    
    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena ) 
      croak("Could not create arena");
   
    nameList = current = CERT_DecodeAltNameExtension(arena, &subAltName);
    if(!current)
      croak("No namelist");

    do {
	switch (current->type) {
	case certDNSName:
            {
            sv_catpv(out, "DNS:");
	    sv_catpvn(out, (const char*) current->name.other.data, current->name.other.len);
            sv_catpv(out, ",");
	    break;
            }
	case certIPAddress:
	    sv_catpv(out, "IP:");
	    sv_catpvn(out, (const char*) current->name.other.data, current->name.other.len);
            sv_catpv(out, ",");
	    break;
	default:
	    sv_catpv(out, "UnknownElement,");
	    break;
	}
	current = CERT_GetNextGeneralName(current);
    } while (current != nameList);
    
    RETVAL = out;

    if (arena) {
	PORT_FreeArena(arena, PR_FALSE);
    }

    if (subAltName.data) {
	SECITEM_FreeItem(&subAltName, PR_FALSE);
    }


  } else {
    croak("Unknown accessor %d", ix);
  }


  OUTPUT:
  RETVAL



SV*
verify_mozilla(cert, timedouble = NO_INIT, usage = certUsageSSLServer)
  NSS::Certificate cert;
  SV* timedouble;
  I32 usage;

  PREINIT:
  SECStatus rv;
  PRTime time = 0;
  CERTCertDBHandle *defaultDB;

  CODE:
  if (cert->serialNumber.data &&
      cert->issuerName &&
      !strcmp(cert->issuerName, 
        "CN=UTN-USERFirst-Hardware,OU=http://www.usertrust.com,O=The USERTRUST Network,L=Salt Lake City,ST=UT,C=US")) {

    unsigned char *server_cert_comparison_start = cert->serialNumber.data;
    unsigned int server_cert_comparison_len = cert->serialNumber.len;

    while (server_cert_comparison_len) {
      if (*server_cert_comparison_start != 0)
        break;

      ++server_cert_comparison_start;
      --server_cert_comparison_len;
    }

    struct nsSerialBinaryBlacklistEntry *walk = myUTNBlacklistEntries;
    for ( ; walk && walk->len; ++walk) {

      unsigned char *locked_cert_comparison_start = (unsigned char*)walk->binary_serial;
      unsigned int locked_cert_comparison_len = walk->len;
      
      while (locked_cert_comparison_len) {
        if (*locked_cert_comparison_start != 0)
          break;
        
        ++locked_cert_comparison_start;
        --locked_cert_comparison_len;
      }

      if (server_cert_comparison_len == locked_cert_comparison_len &&
          !memcmp(server_cert_comparison_start, locked_cert_comparison_start, locked_cert_comparison_len)) {
        PR_SetError(SEC_ERROR_REVOKED_CERTIFICATE, 0);
    	RETVAL = &PL_sv_no;
	return;
        //return SECFailure;
      }
    }
  }

  defaultDB = CERT_GetDefaultCertDB();

  if ( items == 1 ) {
    time = PR_Now();
  } else {
    double tmptime = SvNV(timedouble);
    // time contains seconds since epoch - netscape expects microseconds
    tmptime = tmptime * 1000000;
    LL_D2L(time, tmptime); // and convert to 64-bit int
  }

  rv = CERT_VerifyCert(defaultDB, cert,
                                     PR_TRUE, // check sig 
				     usage,
				     time,
				     NULL,
				     NULL);
  
  if (rv != SECSuccess ) {
    RETVAL = newSViv(PR_GetError()); // return error code
  } else {
    RETVAL = newSViv(1); 
  }

  CERTCertList *certList = NULL;
  certList = CERT_GetCertChainFromCert(cert, PR_Now(), certUsageSSLCA);
  if (!certList) {
    rv = SECFailure;
  } else {
    PRErrorCode blacklistErrorCode;
    if (rv == SECSuccess) { // PSM_SSL_PKIX_AuthCertificate said "valid cert"
      blacklistErrorCode = PSM_SSL_BlacklistDigiNotar(cert, certList);
    } else { // PSM_SSL_PKIX_AuthCertificate said "invalid cert"
      PRErrorCode savedErrorCode = PORT_GetError();
      // Check if we want to worsen the error code to "revoked".
      blacklistErrorCode = PSM_SSL_DigiNotarTreatAsRevoked(cert, certList);
      if (blacklistErrorCode == 0) {
        // we don't worsen the code, let's keep the original error code from NSS
        PORT_SetError(savedErrorCode);
      }
    }
      
    if (blacklistErrorCode != 0) {
      PORT_SetError(blacklistErrorCode);
      SvREFCNT_dec(RETVAL); // kill the old one
      RETVAL = newSViv(blacklistErrorCode); // re-set error code.
      rv = SECFailure;
    }
  }




    if (certList) {
      CERT_DestroyCertList(certList);
    }



  OUTPUT:
  RETVAL

SV*
verify_certificate(cert, timedouble = NO_INIT, usage = certUsageSSLServer)
  NSS::Certificate cert;
  SV* timedouble;
  I32 usage;

  ALIAS:
  verify_certificate_pkix = 1
  verify_cert = 2

  PREINIT:
  SECStatus secStatus;
  PRTime time = 0;
  CERTVerifyLog log;
  CERTCertDBHandle *defaultDB;

  CODE:
  defaultDB = CERT_GetDefaultCertDB();

  if ( items == 1 || SvIV(timedouble) == 0 ) {
    time = PR_Now();
  } else {
    double tmptime = SvNV(timedouble);
    // time contains seconds since epoch - netscape expects microseconds
    tmptime = tmptime * 1000000;
    LL_D2L(time, tmptime); // and convert to 64-bit int
  }

  if ( ix == 1 ) 
    CERT_SetUsePKIXForValidation(PR_TRUE);

  // Initialize log
  log.arena = PORT_NewArena(512);
  log.head = log.tail = NULL;
  log.count = 0;

  if ( ix == 2 ) {

  secStatus = CERT_VerifyCert(defaultDB, cert,
                                     PR_TRUE, // check sig 
				     usage,
				     time,
				     NULL,
				     NULL);
  } else {

  secStatus = CERT_VerifyCertificate(defaultDB, cert,
                                     PR_TRUE, // check sig 
				     cert_usage_to_certificate_usage(usage),
				     time,
				     NULL,
				     &log, NULL);
   }


  if (secStatus != SECSuccess ) {
    RETVAL = newSViv(PR_GetError()); // return error code
  } else {
    RETVAL = newSViv(1); // return 1 on success
  }  

  for (CERTVerifyLogNode *node = log.head; node; node = node->next) {
    if (node->cert)
      CERT_DestroyCertificate(node->cert);
  }
  
  PORT_FreeArena(log.arena, PR_FALSE);

  OUTPUT:
  RETVAL

SV* match_name(cert, string)
  NSS::Certificate cert;
  SV* string;

  PREINIT:
  char* hostname;
  SECStatus secStatus;

  CODE:
  hostname = SvPV_nolen(string);

  secStatus = CERT_VerifyCertName(cert, hostname);

  if ( secStatus != SECSuccess ) {
    RETVAL = &PL_sv_no;
  } else {
    RETVAL = &PL_sv_yes;
  }

  OUTPUT:
  RETVAL

SV*
verify_pkix(cert, timedouble = NO_INIT, usage = certUsageSSLServer, trustedCertList = NO_INIT)
  NSS::Certificate cert;
  SV* timedouble;
  I32 usage;
  NSS::CertList trustedCertList;

  PREINIT:
  SECStatus secStatus;
  PRBool certFetching = PR_FALSE; // automatically get AIA certs

  static CERTValOutParam cvout[4];
  static CERTValInParam cvin[6];
  int inParamIndex = 0;
  static CERTRevocationFlags rev;
  static PRUint64 revFlagsLeaf[2];
  static PRUint64 revFlagsChain[2];
  CERTVerifyLog log;

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

  cvin[inParamIndex].type = cert_pi_revocationFlags;
  cvin[inParamIndex].value.pointer.revocation = &rev;
  inParamIndex++;

  if ( items >= 2 && SvIV(timedouble) > 0 ) {
    PRTime time;
    double tmptime = SvNV(timedouble);
    // time contains seconds since epoch - netscape expects microseconds
    tmptime = tmptime * 1000000;
    LL_D2L(time, tmptime); // and convert to 64-bit int
    cvin[inParamIndex].type = cert_pi_date;
    cvin[inParamIndex].value.scalar.time = time;
    inParamIndex++;
  }
  if ( items == 4 ) {
    // we have a trustedCertList
    cvin[inParamIndex].type = cert_pi_trustAnchors;
    cvin[inParamIndex].value.pointer.chain = trustedCertList;
    inParamIndex++;    
  }

  cvin[inParamIndex].type = cert_pi_end;
  
  // Initialize log
  log.arena = PORT_NewArena(512);
  log.head = log.tail = NULL;
  log.count = 0;

  /* cvout[0].type = cert_po_trustAnchor;
  cvout[0].value.pointer.cert = NULL;
  cvout[1].type = cert_po_certList;
  cvout[1].value.pointer.chain = NULL; 
  cvout[2].type = cert_po_errorLog;
  cvout[2].value.pointer.log = &log; */
  cvout[0].type = cert_po_end;

  secStatus = CERT_PKIXVerifyCert(cert, cert_usage_to_certificate_usage(usage),
                                  cvin, cvout, NULL);
  

  if (secStatus != SECSuccess ) {
    RETVAL = newSViv(PR_GetError()); // return error code
  } else { 
    /* CERTCertificate* issuerCert = cvout[0].value.pointer.cert;
    CERTCertList* builtChain = cvout[1].value.pointer.chain;    

    CERT_DestroyCertList(builtChain);
    CERT_DestroyCertificate(issuerCert); */
   
    RETVAL = newSViv(1);
  }  
    
  // destroy refs in the log 
  for (CERTVerifyLogNode *node = log.head; node; node = node->next) {
    if (node->cert)
      CERT_DestroyCertificate(node->cert);
  }

  PORT_FreeArena(log.arena, PR_FALSE);

  OUTPUT: 
  RETVAL

NSS::Certificate
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
  }
  PORT_Free(item.data);

  RETVAL = cert;

  OUTPUT:
  RETVAL


void DESTROY(cert)
  NSS::Certificate cert;

  PPCODE:

  if ( cert ) {
    if ( cert->nssCertificate ) {
	//printf("Is nsscertificate\n");
	//printf("Refcount: %d\n", cert->nssCertificate->object.refCount);
    }
    //printf("Certificate %s destroyed\n", cert->subjectName);
    CERT_DestroyCertificate(cert);
    cert = 0;
  }

