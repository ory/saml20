import { SignedXml } from 'xml-crypto';
import { select } from 'xpath';
import { parseFromString, thumbprint } from './utils';
import { certToPEM } from './cert';
import { XMLDSIG_NS } from './constants';

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
  /**
   * Maximum number of `Reference` elements accepted in the signature's
   * `SignedInfo`. Defaults to {@link DEFAULT_MAX_SIGNATURE_REFERENCES}. A SAML
   * Response or Assertion signature carries exactly one; the ceiling exists
   * because xml-crypto canonicalizes every Reference (a deep clone of the
   * referenced node, the whole document for `URI=""`) before it verifies
   * `SignatureValue`, so an unbounded, attacker-supplied list costs quadratic
   * CPU before any key is consulted (CWE-407).
   */
  maxSignatureReferences?: number;
}

/**
 * Default ceiling on `SignedInfo/Reference` elements. Generous next to the
 * single Reference a SAML signature carries, while bounding the pre-verification
 * work to a trivial amount.
 */
export const DEFAULT_MAX_SIGNATURE_REFERENCES = 16;

const isMultiCert = (cert) => {
  return cert.indexOf(',') !== -1;
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

const ELEMENT_NODE = 1;

const childElements = (node: Node, localName: string): Element[] => {
  const matches: Element[] = [];
  for (let child = node.firstChild; child; child = child.nextSibling) {
    if (child.nodeType === ELEMENT_NODE && (child as Element).localName === localName) {
      matches.push(child as Element);
    }
  }
  return matches;
};

// Count the Reference children of the signature's SignedInfo children by
// walking the DOM. Equivalent to the XPath
// "./*[local-name(.)='SignedInfo']/*[local-name(.)='Reference']", but linear:
// that XPath takes quadratic time in the number of References in the xpath
// library (about 14 s for 4000), which turned this guard into the very
// CPU cost it exists to prevent.
const countSignedInfoReferences = (signature: Node): number =>
  childElements(signature, 'SignedInfo').reduce(
    (total, signedInfo) => total + childElements(signedInfo, 'Reference').length,
    0
  );

// Refuse a signature whose SignedInfo lists more References than the ceiling.
// Runs before loadSignature/checkSignature, so it costs one XPath count and
// nothing gets canonicalized. Only SignedInfo's direct Reference children are
// counted: that is exactly the set xml-crypto iterates, so a Manifest inside an
// unsigned ds:Object neither inflates the count nor gets a document rejected.
const assertBoundedReferences = (signature, options?: ValidateSignatureOptions) => {
  const max = options?.maxSignatureReferences ?? DEFAULT_MAX_SIGNATURE_REFERENCES;
  // `count > NaN` and `count > Infinity` are both false, so a malformed
  // ceiling would silently switch the guard off. Refuse it instead.
  if (typeof max !== 'number' || !Number.isInteger(max) || max < 0) {
    throw new TypeError(`maxSignatureReferences must be a non-negative integer, got ${String(max)}`);
  }
  const count = countSignedInfoReferences(signature);
  if (count > max) {
    throw new Error(`invalid signature: SignedInfo declares ${count} References; at most ${max} are allowed`);
  }
};

const hasValidSignature = (xml, cert, certThumbprint, options?: ValidateSignatureOptions): string | null => {
  const doc = parseFromString(xml);
  let signature =
    select(
      `/*/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_NS}']`,
      // @ts-expect-error missing Node properties are not needed
      doc!
    )?.[0] ||
    select(
      `/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_NS}']`,
      // @ts-expect-error missing Node properties are not needed
      doc!
    )?.[0] ||
    select(
      `/*/*/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_NS}']`,
      // @ts-expect-error missing Node properties are not needed
      doc!
    )?.[0];

  if (!signature) {
    // @ts-expect-error missing Node properties are not needed
    signature = select("//*[local-name(.)='Signature']", doc!)?.[0];
  }

  if (!signature) {
    // Without this, xml-crypto's loadSignature(undefined) fails with a raw
    // "Cannot read properties of undefined" TypeError.
    throw new Error('invalid signature: no Signature element found');
  }

  const signed = new SignedXml({
    idAttribute: 'AssertionID',
  });

  applyAlgorithmAllowlists(signed, options);

  assertBoundedReferences(signature, options);

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
      // Case B: use a certificate embedded in this signature's KeyInfo, but
      // only one whose thumbprint is trusted.
      if (certThumbprint) {
        if (!keyInfo) {
          return null;
        }
        // Look only inside the KeyInfo of the signature being verified. The
        // first X509Certificate anywhere in the document may belong to another
        // signature or to unsigned content.
        const embeddedCerts = (keyInfo as Element).getElementsByTagNameNS(XMLDSIG_NS, 'X509Certificate');
        const thumbprints = certThumbprint.split(',');
        for (let i = 0; i < embeddedCerts.length; i++) {
          const base64cer = (embeddedCerts[i].textContent || '').trim();
          if (base64cer && thumbprints.includes(thumbprint(base64cer))) {
            return certToPEM(base64cer);
          }
        }
        return null;
      }
      // Case A: use the pre-configured trusted certificate
      return certToPEM(cert);
    };

    valid = signed.checkSignature(xml);
  }

  if (valid && signed.getSignedReferences().length > 0) {
    return signed.getSignedReferences()[0];
  }
  return null;
};

// Returns null when the signature does not verify, and throws when the
// document cannot be checked at all; validate() retries only on null.
const verifySignature = (xml, cert, certThumbprint, options?: ValidateSignatureOptions): string | null => {
  if (cert && certThumbprint) {
    throw new Error('You should provide either cert or certThumbprint, not both');
  }

  return hasValidSignature(sanitizeXML(xml), cert, certThumbprint, options);
};

// Returns the signed XML, which is what callers must read from; throws when
// the signature does not verify.
const validateSignature = (xml, cert, certThumbprint, options?: ValidateSignatureOptions): string => {
  const signedXml = verifySignature(xml, cert, certThumbprint, options);
  if (!signedXml) {
    throw new Error('invalid signature: the signature does not verify');
  }
  return signedXml;
};

const sanitizeXML = (xml) => {
  return xml.replace(/&#x(d|D);/gi, '');
};

export { validateSignature, verifySignature, sanitizeXML };
