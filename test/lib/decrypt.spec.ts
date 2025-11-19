import assert from 'assert';
import { decryptXml } from '../../lib/decrypt';
import fs from 'fs';

/**
 * Generate keys Without or empty  passphrase
 *
 * openssl req -newkey rsa:2048 -new -nodes -keyout key.pem -out csr.pem
 * openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out server.crt
 * openssl dgst -sha1 csr.der //for generating thumbprint or fingerprint
 *
 *
 *
 */

const samlResponseEncrypted = fs.readFileSync('./test/assets/certificates/oktaEncResponse.xml').toString();
const privateKey = fs.readFileSync('./test/assets/certificates/oktaPrivateKey.pem').toString();

const options = {
  privateKey: privateKey,
};
describe('decrypt.ts', function () {
  it('valid xml', function (done) {
    try {
      const { assertion } = decryptXml(samlResponseEncrypted, options);
      assert(assertion);
      done();
    } catch (error) {
      done(error);
    }
  });

  it('empty xml ', function () {
    try {
      decryptXml('', options);
    } catch (error) {
      assert.strictEqual((error as Error).message, 'Undefined Assertion.');
    }
  });
  it('empty privateKey ', function () {
    try {
      decryptXml(samlResponseEncrypted, {
        encPrivateKey: '',
      });
    } catch (error) {
      assert.strictEqual((error as Error).message, 'Exception of Assertion Decryption.');
    }
  });

  it('multiple assertions', function () {
    const multipleAssertionsXml = `
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Assertion1</saml:EncryptedAssertion>
        <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Assertion2</saml:EncryptedAssertion>
      </samlp:Response>
    `;
    try {
      decryptXml(multipleAssertionsXml, options);
    } catch (error) {
      assert.strictEqual((error as Error).message, 'Multiple Assertion.');
    }
  });
});
