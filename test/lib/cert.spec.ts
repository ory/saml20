import assert from 'assert';
import crypto from 'crypto';
import fs from 'fs';
import { stripCertHeaderAndFooter, PubKeyInfo, certToPEM, ensurePemArmor } from '../../lib/cert';
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

describe('cert.ts PEM helpers', function () {
  const BEGIN = '-----BEGIN CERTIFICATE-----';
  const END = '-----END CERTIFICATE-----';

  it('ensurePemArmor adds whichever armor line is missing', function () {
    assert.strictEqual(ensurePemArmor('MIIC'), `${BEGIN}\nMIIC\n${END}`);
    assert.strictEqual(ensurePemArmor(`MIIC\n${END}`), `${BEGIN}\nMIIC\n${END}`);
    assert.strictEqual(ensurePemArmor(`${BEGIN}\nMIIC`), `${BEGIN}\nMIIC\n${END}`);
    assert.strictEqual(ensurePemArmor(`  ${BEGIN}\nMIIC\n${END}\n `), `${BEGIN}\nMIIC\n${END}`);
  });

  it('ensurePemArmor output parses for every armor variant', function () {
    const body = stripCertHeaderAndFooter(
      fs.readFileSync('./test/assets/certificates/testIdpCert.crt').toString()
    );
    for (const variant of [body, `${BEGIN}\n${body}`, `${body}\n${END}`, `${BEGIN}\n${body}\n${END}`]) {
      assert(new crypto.X509Certificate(ensurePemArmor(variant)).validTo);
    }
  });

  it('certToPEM wraps a bare certificate in 64-character lines and leaves PEM alone', function () {
    const pem = certToPEM('A'.repeat(100));
    assert.strictEqual(pem, `${BEGIN}\n${'A'.repeat(64)}\n${'A'.repeat(36)}\n${END}\n`);
    assert.strictEqual(certToPEM(pem), pem);
  });
});
