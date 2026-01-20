import * as assert from 'assert';
import * as fs from 'fs';
import { encryptAssertion, EncryptionAlgorithms } from '../../lib/encrypt';

const publicCert = fs.readFileSync('./test/assets/certificates/oktaPublicKey.crt').toString();

const rawAssertion =
  '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_123">Secret Data</saml:Assertion>';

describe('lib/encrypt.ts', function () {
  this.timeout(5000);

  it('should encrypt a raw assertion string successfully', async () => {
    const result = await encryptAssertion(rawAssertion, {
      publicKey: publicCert,
    });

    assert.ok(result.includes('<saml:EncryptedAssertion'), 'Result should contain <saml:EncryptedAssertion>');
    assert.ok(result.includes('<xenc:EncryptedData'), 'Result should contain <xenc:EncryptedData>');

    assert.ok(!result.includes('Secret Data'), 'Plain text assertion content should be encrypted');
  });

  it('should accept raw base64 key strings (from metadata) and format them', async () => {
    const rawKey = publicCert
      .replace('-----BEGIN CERTIFICATE-----', '')
      .replace('-----END CERTIFICATE-----', '')
      .replace(/\n/g, '');

    const result = await encryptAssertion(rawAssertion, {
      publicKey: rawKey,
    });

    assert.ok(result.includes('<saml:EncryptedAssertion'), 'Should handle raw base64 keys');
  });

  it('should support different encryption algorithms (e.g. GCM)', async () => {
    const result = await encryptAssertion(rawAssertion, {
      publicKey: publicCert,
      encryptionAlgorithm: EncryptionAlgorithms.AES256_GCM,
    });

    assert.ok(
      result.includes('http://www.w3.org/2009/xmlenc11#aes256-gcm'),
      'Should use AES256-GCM algorithm'
    );
  });

  it('should fail with invalid public key', async () => {
    try {
      await encryptAssertion(rawAssertion, {
        publicKey: 'invalid-key-string',
      });
      assert.fail('Should have thrown an error');
    } catch (err: any) {
      assert.ok(err.message, 'Error message should exist');
    }
  });
});
