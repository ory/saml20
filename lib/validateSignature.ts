import { SignedXml } from 'xml-crypto';
import { select } from 'xpath';
import { parseFromString, thumbprint } from './utils';

/**
 * Optional constraints applied while verifying an XML signature.
 *
 * When an allowlist is provided, only the listed algorithm URIs are accepted
 * for that role; a document signed (or digested) with anything else is
 * rejected. When an allowlist is omitted, the permissive defaults from
 * xml-crypto apply (which currently include SHA-1), so existing callers are
 * unaffected.
 *
 * An empty allowlist, or one that names only algorithms xml-crypto does not
 * implement, accepts nothing.
 */
export interface ValidateSignatureOptions {
  /**
   * Accepted `SignatureMethod` algorithm URIs, e.g.
   * `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`.
   */
  allowedSignatureAlgorithms?: string[];
  /**
   * Accepted `DigestMethod` algorithm URIs, e.g.
   * `http://www.w3.org/2001/04/xmlenc#sha256`.
   */
  allowedHashAlgorithms?: string[];
}

const isMultiCert = (cert) => {
  return cert.indexOf(',') !== -1;
};

const certToPEM = (cert) => {
  if (cert.indexOf('BEGIN CERTIFICATE') === -1 && cert.indexOf('END CERTIFICATE') === -1) {
    cert = cert.match(/.{1,64}/g).join('\n');
    cert = '-----BEGIN CERTIFICATE-----\n' + cert;
    cert = cert + '\n-----END CERTIFICATE-----\n';
    return cert;
  } else {
    return cert;
  }
};

// Keep only the entries of an xml-crypto algorithm registry that are named in
// the allowlist. Any lookup for an algorithm outside the result makes
// xml-crypto throw "<kind> algorithm '<uri>' is not supported", so nothing
// outside the allowlist can verify.
const restrictRegistry = <T extends Record<string, unknown>>(registry: T, allowed: string[]): T => {
  const restricted = {} as T;
  for (const uri of allowed) {
    if (Object.prototype.hasOwnProperty.call(registry, uri)) {
      restricted[uri as keyof T] = registry[uri as keyof T];
    }
  }
  return restricted;
};

// Narrow the algorithm registries on a SignedXml instance according to the
// options. The instance is shared by every verification attempt (including
// the multi-certificate loop), so narrowing it once after construction is
// sufficient.
const applyAlgorithmAllowlists = (signed: SignedXml, options?: ValidateSignatureOptions) => {
  if (!options) {
    return;
  }
  if (options.allowedSignatureAlgorithms !== undefined) {
    signed.SignatureAlgorithms = restrictRegistry(
      signed.SignatureAlgorithms,
      options.allowedSignatureAlgorithms
    );
  }
  if (options.allowedHashAlgorithms !== undefined) {
    signed.HashAlgorithms = restrictRegistry(signed.HashAlgorithms, options.allowedHashAlgorithms);
  }
};

// Fail early, with a specific error, when the document declares an algorithm
// outside the allowlists. The narrowed registries above are the actual
// enforcement; this only turns the generic "not supported" (which the
// multi-certificate loop would otherwise swallow) into a clear message.
const assertAllowedAlgorithms = (signed: SignedXml, signature, options?: ValidateSignatureOptions) => {
  if (!options) {
    return;
  }
  if (options.allowedSignatureAlgorithms !== undefined) {
    const signatureAlgorithm = signed.signatureAlgorithm;
    if (!signatureAlgorithm || !signed.SignatureAlgorithms[signatureAlgorithm]) {
      throw new Error(`invalid signature: signature algorithm '${signatureAlgorithm}' is not allowed`);
    }
  }
  if (options.allowedHashAlgorithms !== undefined) {
    // Only SignedInfo's direct Reference children are validated by xml-crypto,
    // so only those DigestMethods are checked here. Scanning the whole
    // Signature subtree would let an unsigned ds:Object/Manifest carrying a
    // disallowed DigestMethod reject an otherwise valid document.
    const digestMethods = select(
      "./*[local-name(.)='SignedInfo']/*[local-name(.)='Reference']/*[local-name(.)='DigestMethod']/@Algorithm",
      signature
    ) as Attr[];
    if (digestMethods.length === 0) {
      throw new Error('invalid signature: no DigestMethod found in signature');
    }
    for (const digestMethod of digestMethods) {
      if (!signed.HashAlgorithms[digestMethod.value]) {
        throw new Error(`invalid signature: digest algorithm '${digestMethod.value}' is not allowed`);
      }
    }
  }
};

// Breaking Change: hasValidSignature now returns:
// if signature is valid: the raw signed xml string
// if signature is invalid: throws error or returns null
// clients are to use the resultant raw xml string to parse their SAML Assertion
// should be internal
const hasValidSignature = (xml, cert, certThumbprint, options?: ValidateSignatureOptions): string | null => {
  xml = sanitizeXML(xml);
  return _hasValidSignature(xml, cert, certThumbprint, options);
};

const _hasValidSignature = (xml, cert, certThumbprint, options?: ValidateSignatureOptions): string | null => {
  const doc = parseFromString(xml);
  let signature =
    select(
      "/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      // @ts-expect-error missing Node properties are not needed
      doc!
    )?.[0] ||
    select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      // @ts-expect-error missing Node properties are not needed
      doc!
    )?.[0] ||
    select(
      "/*/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      // @ts-expect-error missing Node properties are not needed
      doc!
    )?.[0];

  if (!signature) {
    // @ts-expect-error missing Node properties are not needed
    signature = select("//*[local-name(.)='Signature']", doc!)?.[0];
  }

  const signed = new SignedXml({
    idAttribute: 'AssertionID',
  });

  applyAlgorithmAllowlists(signed, options);

  signed.loadSignature(signature);

  assertAllowedAlgorithms(signed, signature, options);

  let valid;
  // Check if cert contains multiple
  // Load each cert and run checkSignature

  // Case A: Use cert(s) i.e. do not use fingerprint
  if (cert && isMultiCert(cert)) {
    const _certs = cert.split(',');
    for (const _cert of _certs) {
      signed.getCertFromKeyInfo = () => {
        return certToPEM(_cert);
      };
      try {
        valid = signed.checkSignature(xml);
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (err) {
        //noop
      }
      if (valid) {
        break;
      }
    }
    if (!valid) {
      throw new Error('invalid signature: Failed to verify signature against all the certificates provided.');
    }
  } else {
    signed.getCertFromKeyInfo = function getKey(keyInfo) {
      // Case A: Let's use the thumbprint
      if (certThumbprint) {
        const embeddedCert = keyInfo!.childNodes[0].ownerDocument!.getElementsByTagNameNS(
          'http://www.w3.org/2000/09/xmldsig#',
          'X509Certificate'
        );

        if (embeddedCert.length > 0) {
          const base64cer = embeddedCert[0].firstChild!.toString();
          // authenticate base64der with trusted fingerprint
          const calculatedThumbprint = thumbprint(base64cer);
          const thumbprints = certThumbprint.split(',');

          if (thumbprints.includes(calculatedThumbprint)) {
            // now we can use it
            return certToPEM(base64cer);
          }
        }
      } else {
        // use pre-configured trusted certificates
        return certToPEM(cert);
      }
    };

    valid = signed.checkSignature(xml);
  }

  if (valid && signed.getSignedReferences().length > 0) {
    return signed.getSignedReferences()[0];
  }
  return null;
};

// Breaking Change: validateSignature now returns:
// if signature is valid: the raw signed xml string
// if signature is invalid: throws error or returns null
// clients are to use the resultant raw xml string to parse their SAML Assertion

const validateSignature = (xml, cert, certThumbprint, options?: ValidateSignatureOptions) => {
  if (cert && certThumbprint) {
    throw new Error('You should provide either cert or certThumbprint, not both');
  }

  return hasValidSignature(xml, cert, certThumbprint, options);
};

const sanitizeXML = (xml) => {
  return xml.replace(/&#x(d|D);/gi, '');
};

export { hasValidSignature, validateSignature, certToPEM, sanitizeXML };
