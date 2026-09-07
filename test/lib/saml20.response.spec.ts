import assert from 'assert';
import { validate } from '../../lib/response';
import fs from 'fs';

// Tests Configuration
const digestValueComment = fs.readFileSync('./test/assets/digestValueComment.xml').toString();
const validResponse = fs.readFileSync('./test/assets/saml20.validResponse.xml').toString();
const validResponseNoIRT = fs.readFileSync('./test/assets/saml20.validResponse-noirt.xml').toString();
const validResponseUnsanitized = fs
  .readFileSync('./test/assets/saml20.validResponse-unsanitized.xml')
  .toString();

const issuerName = 'http://idp.example.com/metadata.php';
const thumbprint = 'e606eced42fa3abd0c5693456384f5931b174707';
const certificate =
  'MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==';
const audience = 'http://sp.example.com/demo1/metadata.php';
const inResponseTo = 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685';

describe('lib.saml20.response', function () {
  it('Should validate saml 2.0 token using thumbprint', async function () {
    const response = await validate(validResponse, {
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

  it('Should honour algorithm allowlists passed to validate()', async function () {
    // saml20.validResponse.xml is signed with RSA-SHA1 / SHA-1
    const sha1Options = {
      allowedSignatureAlgorithms: ['http://www.w3.org/2000/09/xmldsig#rsa-sha1'],
      allowedHashAlgorithms: ['http://www.w3.org/2000/09/xmldsig#sha1'],
    };
    const sha2Options = {
      allowedSignatureAlgorithms: ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'],
      allowedHashAlgorithms: ['http://www.w3.org/2001/04/xmlenc#sha256'],
    };

    const response = await validate(validResponse, {
      publicKey: certificate,
      bypassExpiration: true,
      inResponseTo: inResponseTo,
      ...sha1Options,
    });
    assert.strictEqual(response.issuer, issuerName);

    await assert.rejects(
      validate(validResponse, {
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
        ...sha2Options,
      }),
      (err: any) => {
        assert.strictEqual(err.message, 'Invalid assertion.');
        assert.match(err.inner.message, /signature algorithm '.*rsa-sha1' is not allowed/);
        return true;
      }
    );

    // thumbprint path
    await assert.rejects(
      validate(validResponse, {
        thumbprint: thumbprint,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
        allowedHashAlgorithms: sha2Options.allowedHashAlgorithms,
      }),
      (err: any) => {
        assert.match(err.inner.message, /digest algorithm '.*sha1' is not allowed/);
        return true;
      }
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

  it('Should validate saml 2.0 token skipping InResponseTo validation', async function () {
    const response = await validate(validResponseNoIRT, {
      publicKey: certificate,
      audience: audience,
      bypassExpiration: true,
      inResponseTo: inResponseTo,
    });
    assert.strictEqual(response.issuer, issuerName);
  });

  it('Should validate unsanitized saml 2.0 token using thumbprint', async function () {
    const response = await validate(validResponseUnsanitized, {
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

  it('Should validate unsanitized saml 2.0 token using certificate', async function () {
    const response = await validate(validResponseUnsanitized, {
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

  it('Should fail with invalid signature', async function () {
    try {
      await validate(digestValueComment, {
        publicKey: `MIIDzzCCAregAwIBAgIUMZMb3dfDNPcYK9rYUCz6U/Y/vdwwDQYJKoZIhvcN
AQELBQAwdzELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMREwDwYDVQQH
DAhMb2NhdGlvbjEVMBMGA1UECgwMT3JnYW5pemF0aW9uMREwDwYDVQQLDAhP
cmcgVW5pdDEbMBkGA1UEAwwScG9jLnNlY3VyZXNhbWwuY29tMB4XDTI0MTEy
ODA1NDYyN1oXDTM0MTEyNjA1NDYyN1owdzELMAkGA1UEBhMCVVMxDjAMBgNV
BAgMBVN0YXRlMREwDwYDVQQHDAhMb2NhdGlvbjEVMBMGA1UECgwMT3JnYW5p
emF0aW9uMREwDwYDVQQLDAhPcmcgVW5pdDEbMBkGA1UEAwwScG9jLnNlY3Vy
ZXNhbWwuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArBx4
nG94nZJvXMSWkkJMxWMTY5YS53MegLD/DOMgM5n5tXBRewAgFkEdL6tclvqK
EP80yc5N/KSdGZrbwD5oKhw4+4+GTpRSSoleFLhSYr0DZvTMvFHMgB45SddU
A3DkcI0ZSF+RExZQhMypYxNjEMkKL5EJDh7d+Xt9FCVQ1GKjVRI12jeXOvTQ
TOefPaz314aFBJ0XfqP3tl08jJAWC2kOgi9vB43Xu7u//FgubRifhwcVkzFt
WLdDJSm/Q3qHkV8QDb4TL54dGHdXUP8wo0msqt2WXGZ691VYrRXw8dYmthl7
KeVwcBsUUbUr2jA+Ia2hxnbBTfPY2m9ZfKEBUQIDAQABo1MwUTAdBgNVHQ4E
FgQUknvBAHKXFwZjDB0rSvTGi2e/7n0wHwYDVR0jBBgwFoAUknvBAHKXFwZj
DB0rSvTGi2e/7n0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAj9BFFl9jSvmR/3GipWuBAC84jEdEzLk6o8AgqZGdBABFAK3TURlQLTli
Nj17zqOlr3xHBorX9iCk46IZZ5ARjjjwzQZ5mzGsMYp+LPlC+w9G1AsqwXCL
619+JQ5ORHN7kMHgQYIzkKe8FRa0NjBAl0FIwCe0DWGrbuNrQB5p5h/77TTF
N+/ESjVbK0m/ubsl4tBnDqR3aq7KiBNr0e1yTF17Gg5iHc1ofINzq5i30/4v
GGw0ohtr4ihg6J3hdwUIVnRknfuN3tE80jSF4e1LRojlyFoQXcg4emXq0Jn8
lj6sw9dhQDq19MYaXchAuJMkWmXwt9e/CaWm7JRyuUgBcg==`,
        audience: 'https://poc.securesaml.com/sp/acs',
        bypassExpiration: true,
      });
    } catch (error) {
      const result = (error as Error).message;
      console.log('result:', result);
      assert.strictEqual(result, 'Invalid assertion signature.');
    }
  });
});
