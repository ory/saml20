import assert from 'assert';
import { stripCertHeaderAndFooter, PubKeyInfo } from '../../lib/cert';
import { parseFromString } from '../../lib/utils';

const certificate =
  'MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==';

describe('cert.ts', function () {
  it('stripCertHeaderAndFooter ok', function () {
    assert(stripCertHeaderAndFooter(certificate));
  });
  it('stripCertHeaderAndFooter not ok', function () {
    assert.strictEqual(stripCertHeaderAndFooter(''), '');
  });

  it('PubKeyInfo ok', function () {
    assert.strictEqual(
      PubKeyInfo(certificate)({ prefix: '' }),
      `<X509Data><X509Certificate>${certificate}</X509Certificate></X509Data>`
    );
  });

  it('PubKeyInfo applies the namespace prefix to every tag', function () {
    assert.strictEqual(
      PubKeyInfo('MIIC')({ prefix: 'ds' }),
      '<ds:X509Data><ds:X509Certificate>MIIC</ds:X509Certificate></ds:X509Data>'
    );
  });

  it('PubKeyInfo produces well-formed XML', function () {
    const keyInfo = PubKeyInfo(`-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----\n`)({
      prefix: 'ds',
    });
    const doc = parseFromString(
      `<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${keyInfo}</ds:KeyInfo>`
    );
    const certs = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate');
    assert.strictEqual(certs.length, 1);
    assert.strictEqual(certs[0].textContent, certificate);
  });
});
