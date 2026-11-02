import { describe, it } from 'node:test';
import assert from 'node:assert';
import { parseIssuer, validate } from '../../lib/response';
import { multiRootedXMLError } from '../../lib/utils';
import fs from 'fs';

const certificate =
  'MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==';

const audience = 'http://sp.example.com/demo1/metadata.php';

// Evil response that contains multiple root elements
const multipleRootElements = fs
  .readFileSync('./test/assets/attacks/saml20.response.multipleRootElements.xml')
  .toString();

describe('saml20.attacks', () => {
  describe('multiple roots => invalid', () => {
    it('validate', async () => {
      try {
        await validate(multipleRootElements, {
          publicKey: certificate,
          audience,
          bypassExpiration: true,
        });
      } catch (error) {
        const result = (error as Error).message;
        assert.strictEqual(result, multiRootedXMLError.message);
      }
    });

    it('parseIssuer', () => {
      try {
        parseIssuer(multipleRootElements);
      } catch (error) {
        const result = (error as Error).message;
        assert.strictEqual(result, multiRootedXMLError.message);
      }
    });
  });
});
