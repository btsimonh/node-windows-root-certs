

if (process.platform === 'win32'){
  var ffi = require('ffi');
  var ref = require('ref');
  var Struct = require('ref-struct');

/*
typedef struct _CERT_CONTEXT {
  DWORD      dwCertEncodingType;
  BYTE       *pbCertEncoded;
  DWORD      cbCertEncoded;
  PCERT_INFO pCertInfo;
  HCERTSTORE hCertStore;
} CERT_CONTEXT, *PCERT_CONTEXT;

typedef struct _CRYPTOAPI_BLOB {
  DWORD cbData;
  BYTE  *pbData;
} CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB, CRYPT_UINT_BLOB, *PCRYPT_UINT_BLOB, CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB, CERT_NAME_BLOB, CERT_RDN_VALUE_BLOB, *PCERT_NAME_BLOB, *PCERT_RDN_VALUE_BLOB, CERT_BLOB, *PCERT_BLOB, CRL_BLOB, *PCRL_BLOB, DATA_BLOB, *PDATA_BLOB, CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB, CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB, CRYPT_DIGEST_BLOB, *PCRYPT_DIGEST_BLOB, CRYPT_DER_BLOB, PCRYPT_DER_BLOB, CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB;

typedef struct _CRYPT_BIT_BLOB {
  DWORD cbData;
  BYTE  *pbData;
  DWORD cUnusedBits;
} CRYPT_BIT_BLOB, *PCRYPT_BIT_BLOB;


typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
  LPSTR            pszObjId;
  CRYPT_OBJID_BLOB Parameters;
} CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;

typedef struct _FILETIME {
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef struct _CERT_PUBLIC_KEY_INFO {
  CRYPT_ALGORITHM_IDENTIFIER Algorithm;
  CRYPT_BIT_BLOB             PublicKey;
} CERT_PUBLIC_KEY_INFO, *PCERT_PUBLIC_KEY_INFO;

typedef struct _CERT_EXTENSION {
  LPSTR            pszObjId;
  BOOL             fCritical;
  CRYPT_OBJID_BLOB Value;
} CERT_EXTENSION, *PCERT_EXTENSION;

typedef struct _CERT_INFO {
  DWORD                      dwVersion;
  CRYPT_INTEGER_BLOB         SerialNumber;
  CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
  CERT_NAME_BLOB             Issuer;
  FILETIME                   NotBefore;
  FILETIME                   NotAfter;
  CERT_NAME_BLOB             Subject;
  CERT_PUBLIC_KEY_INFO       SubjectPublicKeyInfo;
  CRYPT_BIT_BLOB             IssuerUniqueId;
  CRYPT_BIT_BLOB             SubjectUniqueId;
  DWORD                      cExtension;
  PCERT_EXTENSION            rgExtension;
} CERT_INFO, *PCERT_INFO;


typedef struct _CERT_CONTEXT {
  DWORD      dwCertEncodingType;
  BYTE       *pbCertEncoded;
  DWORD      cbCertEncoded;
  PCERT_INFO pCertInfo;
  HCERTSTORE hCertStore;
} CERT_CONTEXT, *PCERT_CONTEXT;
*/

  const DATA_BLOB = Struct({
    cbData: ref.types.uint32,
    pbData: ref.refType(ref.types.byte)
  });
  const PDATA_BLOB = new ref.refType(DATA_BLOB);
  
  const CRYPT_BIT_BLOB = Struct({
    cbData: ref.types.uint32,
    pbData: ref.refType(ref.types.byte),
    cUnusedBits: ref.types.uint32,
  });
  
  const CRYPT_ALGORITHM_IDENTIFIER = Struct({
    pszObjId: 'string',
    Parameters: DATA_BLOB
  });
  
  const FILETIME = Struct({
    dwLowDateTime: ref.types.uint32,
    dwHighDateTime: ref.types.uint32,
  });
 
  const CERT_PUBLIC_KEY_INFO = Struct({
    Algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    PublicKey: CRYPT_BIT_BLOB,
  });
 
  const CERT_EXTENSION = Struct({
    pszObjId: 'string',
    fCritical: 'bool',
    Value: DATA_BLOB,
  });

  const PCERT_EXTENSION = new ref.refType(CERT_EXTENSION);
  
  const CERT_INFO = Struct({
    dwVersion: ref.types.uint32,
    SerialNumber: DATA_BLOB,
    SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    Issuer: DATA_BLOB,
    NotBefore: FILETIME,
    NotAfter: FILETIME,
    Subject: DATA_BLOB,
    SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO,
    IssuerUniqueId: CRYPT_BIT_BLOB,
    SubjectUniqueId: CRYPT_BIT_BLOB,
    cExtension:ref.types.uint32,
    rgExtension: PCERT_EXTENSION,
  });
  const PCERT_INFO = new ref.refType(CERT_INFO);
  
  const CERT_CONTEXT = Struct({
    dwCertEncodingType: ref.types.uint32,
    pbCertEncoded: 'pointer', 
    cbCertEncoded: ref.types.uint32,
    pCertInfo: PCERT_INFO,
    hCertStore: 'pointer',
  });
  const PCERT_CONTEXT = new ref.refType(CERT_CONTEXT);
  
  const Crypto = new ffi.Library('Crypt32', {
      CertOpenSystemStoreA: [ 'void *', ['void *', 'string']],
      CertEnumCertificatesInStore: [ PCERT_CONTEXT, ['void *', PCERT_CONTEXT]],
      CertFreeCertificateContext: [ 'bool', [PCERT_CONTEXT] ],
      CertCloseStore: [ 'bool', ['void *', 'void *']],
  });

  function dumpblob(b, encoding) {
    if (!encoding) encoding = 'ascii';
    //console.log(b.cbData);
    if (b.cbData < 10000) {
      var text = ref.reinterpret(b.pbData, b.cbData, 0);
      return text.toString(encoding);
    }
    return 'too big';
  }
  
  function splitSlice(str, len) {
    var ret = [ ];
    for (var offset = 0, strLen = str.length; offset < strLen; offset += len) {
      ret.push(str.slice(offset, len + offset));
    }
    return ret;
  }
  
  function getCerts(StoreName, options) {
    if (!StoreName) {
      StoreName = 'ROOT';
    }
    var certs = [];
    
    if (!options) {
      options = {};
    }
    
    if (!options.maxcerts) {
      options.maxcerts = 300;
    }
    
    const hStoreHandle = Crypto.CertOpenSystemStoreA(null, StoreName);
    var pCertContext = null;   
    if (!ref.isNull(hStoreHandle)){
      //console.log("The "+StoreName+" store has been opened as ", hStoreHandle);
    } else {
      throw new Error('The '+StoreName+' store failed to open.');
    }
    
    var maxcerts = options.maxcerts;
    var quit = 0;
    
    // Find the certificates in the system store. 
    while(!quit && (maxcerts > 0)) 
    {
      // on the first call to the function, 
      // this parameter is NULL 
      // on all subsequent calls, 
      // this parameter is the last pointer 
      // returned by the function      
      pCertContext = Crypto.CertEnumCertificatesInStore(hStoreHandle,pCertContext);
      
      if (!ref.isNull(pCertContext)) {
        var CertContext = pCertContext.deref();
        var CertEncodedLen = CertContext.cbCertEncoded;
        let binary = ref.reinterpret(CertContext.pbCertEncoded, CertEncodedLen, 0);
        var CertInfo = CertContext.pCertInfo.deref();
        var base64 = binary.toString('base64');
        var lines = splitSlice(base64, 72);
        lines.unshift('-----BEGIN CERTIFICATE-----');
        lines.push('-----END CERTIFICATE-----');
        var pem = lines.join('\n');
        certs.push(pem);
        if (maxcerts-- <= 0) 
          break;
      } else {
        quit = 1;
      }
    } // End of while.

    // if we ran out of maxcerts, should dispose of current
    if (!ref.isNull(pCertContext)) {
      Crypto.CertFreeCertificateContext(pCertContext);
      pCertContext = null;
    }
    
    //--------------------------------------------------------------------
    //   Clean up.
    if (!Crypto.CertCloseStore(hStoreHandle, null)) {
        console.log("Failed CertCloseStore");
    }
    
    return certs;
  }
   
} else {
   function getCerts(StoreName, options) {
     console.log('not windows');
     return [];
   }
}

var tlsOptions = {
  includeNodeCerts: false,
  orgCreateSecureContext: null,
};

function patchTls( certs, options ) {
  var tls = require('tls');
  
  if (!tlsOptions.orgCreateSecureContext) {
      tlsOptions.orgCreateSecureContext = tls.createSecureContext;
  }

  if (options && options.includeNodeCerts !== undefined) {
    tlsOptions.includeNodeCerts = options.includeNodeCerts;
  }

  var newCreateSecureContext = function(options) {
    if (!options){
        options = {};
    }
    
    if (!options.ca){
      if (tlsOptions.includeNodeCerts) {
        options.ca = tls.rootCertificates.slice(0);
      } else {
        options.ca = [];
      }
    }
    options.ca = options.ca.concat(certs);
    //console.log("options", options.ca);
    return tlsOptions.orgCreateSecureContext.bind(tls)(options);
  }

  tls.createSecureContext = newCreateSecureContext.bind(tls);
}

function unPatchTls(){
  if (tlsOptions.orgCreateSecureContext) {
     tls.createSecureContext = tlsOptions.orgCreateSecureContext;
     tlsOptions.orgCreateSecureContext = null;
  }
}

function useWindowsCerts(){
  var certs = getCerts();
  patchTls(certs);
}

module.exports = {
  // functions
  getCerts: getCerts,
  patchTls: patchTls,
  unPatchTls: unPatchTls,
  useWindowsCerts: useWindowsCerts,
  
  // variables
  tlsOptions: tlsOptions,
};
