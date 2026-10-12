import assert from 'assert';
import { decryptXml } from '../../lib/decrypt';
import { validate } from '../../lib/response';
import { multiRootedXMLError, WrapError } from '../../lib/utils';
import * as xmlenc from 'xml-encryption';
import { promisify } from 'util';
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

const testIdpCert = fs.readFileSync('./test/assets/certificates/testIdpCert.crt').toString();
const testIdpPrivateKey = fs.readFileSync('./test/assets/certificates/testIdpKey.pem').toString();

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
    assert.throws(() => decryptXml('', options), { message: 'Undefined Assertion.' });
  });
  it('empty privateKey ', function () {
    assert.throws(
      () => decryptXml(samlResponseEncrypted, { privateKey: '' }),
      (error: WrapError) => {
        assert(error instanceof WrapError);
        assert.strictEqual(error.message, 'Exception of Assertion Decryption.');
        assert.match(error.inner.message, /key option is mandatory/);
        return true;
      }
    );
  });
  it('wrong privateKey keeps the underlying error in inner', function () {
    assert.throws(
      () => decryptXml(samlResponseEncrypted, { privateKey: testIdpPrivateKey }),
      (error: WrapError) => {
        assert(error instanceof WrapError);
        assert.strictEqual(error.message, 'Exception of Assertion Decryption.');
        assert(error.inner instanceof Error);
        return true;
      }
    );
  });

  it('multiple assertions', function () {
    const multipleAssertionsXml = `
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Assertion1</saml:EncryptedAssertion>
        <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Assertion2</saml:EncryptedAssertion>
      </samlp:Response>
    `;
    assert.throws(() => decryptXml(multipleAssertionsXml, options), { message: 'Multiple Assertion.' });
  });

  describe('errors after decryption', function () {
    const encryptToResponse = async (plaintext: string) => {
      const encrypted = await promisify(xmlenc.encrypt)(plaintext, {
        rsa_pub: testIdpCert,
        pem: testIdpCert,
        encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
        keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
      });
      return (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0">' +
        `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${encrypted}</saml:EncryptedAssertion>` +
        '</samlp:Response>'
      );
    };

    it('decrypts a well-formed assertion once', async function () {
      const response = await encryptToResponse(
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a" Version="2.0"/>'
      );
      const { assertion, decrypted } = decryptXml(response, { privateKey: testIdpPrivateKey });
      assert.strictEqual(decrypted, true);
      assert.strictEqual(assertion.match(/<saml:Assertion /g)?.length, 1);
      assert(!assertion.includes('EncryptedAssertion'));
    });

    it('surfaces a multi-rooted decrypted payload as the multi-root error', async function () {
      const response = await encryptToResponse(
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"/>' +
          '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_b"/>'
      );
      assert.throws(() => decryptXml(response, { privateKey: testIdpPrivateKey }), multiRootedXMLError);
      await assert.rejects(
        validate(response, {
          audience: 'https://sp.example.com/metadata',
          privateKey: testIdpPrivateKey,
          publicKey: testIdpCert,
        }),
        multiRootedXMLError
      );
    });
  });
});
