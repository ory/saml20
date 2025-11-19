import assert from 'assert';
import { sign } from '../../lib/sign';
import fs from 'fs';

const validXml = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>me</saml:Issuer></saml:Assertion>';
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
