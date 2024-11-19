# node-windows-root-certs

Enables use of Windows root certificates in nodejs directly, without environment settings or certificate files.

Tested on node 12.10.0

For node 18-22, please use [node-windows-root-certs-napi](https://github.com/YellaUmbrella-tv/node-windows-root-certs-napi)

# Uses for this module:

## In a coporate envionment 

If they have a WAF (Web Application Firewall - a man in the middle), the root certificate for the WAF is often installed as a certificate in Windows.  NodeJS has no access to this certifcate, and so nodeJS based applications will fail without special measures.

## You need to https or tls to a server with a self signed certificate

Enables the root certificate for your server to be added, either by adding in Windows, or manually.

I tried but failed to get this to work in test.js with badssl.com :(

## For 'Older' versions of NodeJS

If the certificates inside NodeJS expire, the application will stop working....


# What it does

This module provides two features:

## reading of the Windows root certificates

A function is provided to read the Windows Root certifcates returning an array similar to node's own rootcertificates array.

## patching tls

A function is provided which will patch the tls module such that all HTTPS or other tls based secure communication will use the provided certificates - either a complete certificate list or, a list additional to the internal nodeJS list.

Note: if tls is patched AFTER a successful connection to a site, then it's likely that the new/modified certificates will not be used for a subsequent connection, as the connection itself may be cached.

# Usage

`npm install node-windows-root-certs`

```
var windowsRootCerts = require('node-windows-root-certs');

// to read windows root certs
var rootCerts = windowsRootCerts.getCerts();

// result:
// ["-----BEGIN CERTIFICATE-----\nMIIF.....Da\n-----END CERTIFICATE-----","-----BEGIN CERTIFICATE-----...."]

// to patch tls with any cert list as above:
windowsRootCerts.patchTls( rootCerts );
```

or

```
var windowsRootCerts = require('node-windows-root-certs');
// to read the windows root certs and patch in a single command:
windowsRootCerts.useWindowsCerts();
```

or - to add just some additional known certificates to the end of the existing NodeJS set:

```
var windowsRootCerts = require('node-windows-root-certs');
var mycerts = [
  "-----BEGIN CERTIFICATE-----\nMIIF.....Da\n-----END CERTIFICATE-----",
  "-----BEGIN CERTIFICATE-----...."
];
windowsRootCerts.patchTls( mycerts, { includeNodeCerts:true } );

```

# test

`npm test`

will access `https://google.com` using windows certificates.


# exports

```
module.exports = {
  // functions
  getCerts: getCerts, 
  patchTls: patchTls,
  unPatchTls: unPatchTls,
  useWindowsCerts: useWindowsCerts,
  
  // variables
  tlsOptions: tlsOptions,
};
```

## getCerts

Reads a list of certificates from a named Windows certificate store.

var certs = windowsRootCerts.getCerts(StoreName, Options);

parameters:

StoreName - the name of the Windows certificate store to read, default 'ROOT'

Options - default { maxcerts: 300 } - maxcerts limits the number of certificates retrieved.  My machine had ~90.

returns: an array of strings, each being a certificate.

## patchTls

Patches the nodejs tls module to either replace the NodeJS root certificate list, or add to it.

windowsRootCerts.patchTls( certsArray, options );

parameters:

certsArray - an array of strings, each being a base64 encoded certificate like:

`"-----BEGIN CERTIFICATE-----\nMIIF.....Da\n-----END CERTIFICATE-----"`

options - default { includeNodeCerts:false } - if includeNodeCerts is true, then the certs supplied are Appended to the normal NodeJS root certificate list.

## unPatchTls

Restores tls to original.

windowsRootCerts.unPatchTls();

## tlsOptions

Object which stores the options fields used in patchTls()

console.log(windowsRootCerts.tlsOptions);


# Technology

windows-root-certs uses 

```
    "ffi": "lxe/node-ffi#node-12",
    "ref": "javihernandez/ref#node-12",
    "ref-struct": "javihernandez/ref-struct#node-12"
```

In combination, these provide the ability to call windows dll functions directly from nodejs.  In this case we use the following functions from Crypt32.dll:


```
  CertOpenSystemStoreA: [ 'void *', ['void *', 'string']],
  CertEnumCertificatesInStore: [ PCERT_CONTEXT, ['void *', PCERT_CONTEXT]],
  CertFreeCertificateContext: [ 'bool', [PCERT_CONTEXT] ],
  CertCloseStore: [ 'bool', ['void *', 'void *']],
```

to read a windows certificate store and extract the certificates for use in node.

tls is patched by replacing tls.createSecureContext with our own function, which extends or adds options to include the new certifcates before calling the original tls.createSecureContext function.

# Credits

The use of windows API functions directly in node would not be possible without the contributions of @TooTallNate (https://github.com/TooTallNate) - wish he would update his repos for node 12!

Thanks to these repos for inspiration:

https://github.com/ukoloff/win-ca

https://github.com/capriza/syswide-cas


