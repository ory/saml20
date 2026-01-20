import { SignedXml } from 'xml-crypto';
import { PubKeyInfo } from './cert';
import { SignOptions } from './typings';

const issuerXPath = '/*[local-name(.)="Issuer" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:assertion"]';

/**
 * Signs a specific element within the XML string using RSA-SHA256.
 * Preserves the logic for KeyInfo content and Canonicalization algorithms.
 *
 * @param {string} xml - The raw XML string containing the element to be signed.
 * @param {ISignOptions} options - Configuration options including keys and target location.
 * @returns {string} The XML string with the embedded <ds:Signature>.
 * @throws {Error} If xml or signingKey is missing.
 */
const sign = (xml: string, options: SignOptions): string => {
  const { privateKey: signingKey, publicKey, sigLocation: xPath } = options;

  if (!xml) {
    throw new Error('Please specify xml');
  }
  if (!signingKey) {
    throw new Error('Please specify signingKey');
  }

  const sig = new SignedXml({
    privateKey: signingKey,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    getKeyInfoContent: PubKeyInfo(publicKey),
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath: xPath,
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  sig.computeSignature(xml, {
    location: {
      reference: xPath + issuerXPath,
      action: 'after'
    },
  });

  return sig.getSignedXml();
};

export { sign };
