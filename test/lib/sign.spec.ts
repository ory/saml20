import assert from 'assert';
import { sign } from '../../lib/sign';
import { validateSignature } from '../../lib/validateSignature';
import { stripCertHeaderAndFooter } from '../../lib/cert';
import { thumbprint } from '../../lib/utils';
import fs from 'fs';

const validXml =
  '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>me</saml:Issuer></saml:Assertion>';
const signingKey = fs.readFileSync('./test/assets/certificates/oktaPrivateKey.pem').toString();
const publicKey = fs.readFileSync('./test/assets/certificates/oktaPublicKey.crt').toString();

describe('sign.ts', function () {
  it('should sign valid XML', function () {
    const signed = sign(validXml, signingKey, publicKey, '/*[local-name(.)="Assertion"]');
    assert(signed);
    assert(signed.includes('Signature'));
  });

  it('should throw error if xml is missing', function () {
    assert.throws(() => sign('', signingKey, publicKey, ''), /Please specify xml/);
  });

  it('should throw error if signingKey is missing', function () {
    assert.throws(() => sign(validXml, '', publicKey, ''), /Please specify signingKey/);
  });
});

describe('sign.ts output', function () {
  const cert = fs.readFileSync('./test/assets/certificates/testIdpCert.crt').toString();
  const key = fs.readFileSync('./test/assets/certificates/testIdpKey.pem').toString();
  const assertionXPath = '/*[local-name(.)="Assertion"]';

  it('uses RSA-SHA256, SHA-256 digests and places the Signature right after the Issuer', function () {
    const signed = sign(validXml, key, cert, assertionXPath);
    assert(
      signed.includes('<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>')
    );
    assert(signed.includes('<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'));
    assert(/<\/saml:Issuer><Signature /.test(signed));
  });

  it('verifies against the configured certificate', function () {
    const signed = sign(validXml, key, cert, assertionXPath);
    assert(validateSignature(signed, cert, null));
  });

  it('embeds a KeyInfo certificate that matches the signing certificate thumbprint', function () {
    const signed = sign(validXml, key, cert, assertionXPath);
    const signedReference = validateSignature(signed, null, thumbprint(stripCertHeaderAndFooter(cert)));
    assert(signedReference);
  });

  it('does not verify after the signed content changes', function () {
    const signed = sign(validXml, key, cert, assertionXPath);
    assert.strictEqual(validateSignature(signed.replace('>me<', '>you<'), cert, null), null);
  });
});
