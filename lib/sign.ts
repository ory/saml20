import { SignedXml } from 'xml-crypto';
import { PubKeyInfo } from './cert';
import { ASSERTION_NS } from './constants';

const issuerXPath = `/*[local-name(.)="Issuer" and namespace-uri(.)="${ASSERTION_NS}"]`;

const sign = (xml: string, signingKey: string, publicKey: string, xPath: string) => {
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
    location: { reference: xPath + issuerXPath, action: 'after' },
  });

  return sig.getSignedXml();
};

export { sign };
