import assert from 'assert';
import { validate } from '../../lib/response';
import fs from 'fs';

// Tests Configuration
const validResponse = fs.readFileSync('./test/assets/saml20.validResponseSignedMessage.xml').toString();
const validResponseUnsanitized = fs
  .readFileSync('./test/assets/saml20.validResponseSignedMessage-unsanitized.xml')
  .toString();

const issuerName = 'http://idp.example.com/metadata.php';
const thumbprint = 'e606eced42fa3abd0c5693456384f5931b174707';
const certificate =
  'MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==';
const audience = 'http://sp.example.com/demo1/metadata.php';
const inResponseTo = 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685';

describe('saml20.responseSignedMessage', function () {
  it('Should validate saml 2.0 token using thumbprint', async function () {
    const response = await validate(validResponse, {
      audience,
      thumbprint: thumbprint,
      bypassExpiration: true,
      inResponseTo: inResponseTo,
    });

    assert.strictEqual(response.issuer, issuerName);
    assert.strictEqual(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
      '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7'
    );
  });

  it('Should validate saml 2.0 token using certificate', async function () {
    const response = await validate(validResponse, {
      audience,
      publicKey: certificate,
      bypassExpiration: true,
      inResponseTo: inResponseTo,
    });

    assert.strictEqual(response.issuer, issuerName);
    assert.strictEqual(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
      '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7'
    );
  });

  it('Should validate saml 2.0 token and check audience', async function () {
    const response = await validate(validResponse, {
      publicKey: certificate,
      audience: audience,
      bypassExpiration: true,
      inResponseTo: inResponseTo,
    });
    assert.strictEqual(response.issuer, issuerName);
  });

  it('Should fail with invalid audience', async function () {
    try {
      await validate(validResponse, {
        publicKey: certificate,
        audience: 'http://any-other-audience.com/',
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid audience.');
    }
  });

  it('Should fail with missing root element', async function () {
    try {
      await validate('invalid-assertion', {
        audience,
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'missing root element');
    }
  });

  it('Should fail with invalid inResponseTo', async function () {
    try {
      await validate(validResponse, {
        publicKey: certificate,
        audience: audience,
        bypassExpiration: true,
        inResponseTo: 'not-the-right-response-to',
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid InResponseTo.');
    }
  });
});

describe('saml20.validResponseSignedMessageUnsanitized', function () {
  it('Should validate saml 2.0 token using thumbprint', async function () {
    const response = await validate(validResponseUnsanitized, {
      audience,
      thumbprint: thumbprint,
      bypassExpiration: true,
      inResponseTo: inResponseTo,
    });

    assert.strictEqual(response.issuer, issuerName);
    assert.strictEqual(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
      '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7'
    );
  });

  it('Should validate saml 2.0 token using certificate', async function () {
    const response = await validate(validResponseUnsanitized, {
      audience,
      publicKey: certificate,
      bypassExpiration: true,
      inResponseTo: inResponseTo,
    });

    assert.strictEqual(response.issuer, issuerName);
    assert.strictEqual(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
      '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7'
    );
  });

  it('Should validate saml 2.0 token and check audience', async function () {
    const response = await validate(validResponseUnsanitized, {
      publicKey: certificate,
      audience: audience,
      bypassExpiration: true,
      inResponseTo: inResponseTo,
    });
    assert.strictEqual(response.issuer, issuerName);
  });

  it('Should fail with invalid audience', async function () {
    try {
      await validate(validResponseUnsanitized, {
        publicKey: certificate,
        audience: 'http://any-other-audience.com/',
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid audience.');
    }
  });

  it('Should fail with missing root element', async function () {
    try {
      await validate('invalid-assertion', {
        audience,
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'missing root element');
    }
  });

  it('Should fail with invalid inResponseTo', async function () {
    try {
      await validate(validResponseUnsanitized, {
        publicKey: certificate,
        audience: audience,
        bypassExpiration: true,
        inResponseTo: 'not-the-right-response-to',
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid InResponseTo.');
    }
  });
});
