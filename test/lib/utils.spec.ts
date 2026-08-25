import assert from 'assert';
import {
  parseFromString,
  thumbprint,
  getAttribute,
  isMultiRootedXMLError,
  doctypeNotAllowedError,
  containsDoctype,
} from '../../lib/utils';

describe('utils.ts', function () {
  describe('parseFromString', function () {
    it('should parse valid XML', function () {
      const xml = '<root>test</root>';
      const doc = parseFromString(xml);
      assert(doc);
      assert(doc.documentElement);
      assert.strictEqual(doc.documentElement.nodeName, 'root');
    });

    it('should throw error for invalid XML', function () {
      assert.throws(() => parseFromString('<root>unclosed'), /unclosed xml tag/);
    });

    it('should throw error for multi-rooted XML', function () {
      assert.throws(() => parseFromString('<root></root><root></root>'), /multirooted xml not allowed/);
    });

    it('should throw error for empty XML', function () {
      assert.throws(() => parseFromString(''), /missing root element/);
    });

    // A DTD has no legitimate place in SAML XML and enables XXE-class attacks.
    // See https://github.com/ory/polis/issues/4071.
    it('should reject XML that declares a DOCTYPE', function () {
      const xml = '<?xml version="1.0"?>\n<!DOCTYPE foo>\n<root>test</root>';
      assert.throws(() => parseFromString(xml), doctypeNotAllowedError);
    });

    it('should reject a DOCTYPE with an internal entity subset (XXE payload)', function () {
      const xml =
        '<?xml version="1.0"?>\n' +
        '<!DOCTYPE foo [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>\n' +
        '<root>&x;</root>';
      assert.throws(() => parseFromString(xml), doctypeNotAllowedError);
    });

    it('should accept valid XML that does not declare a DOCTYPE', function () {
      const doc = parseFromString('<?xml version="1.0"?><root><a>hi</a></root>');
      assert(doc);
      assert.strictEqual(doc.documentElement?.nodeName, 'root');
    });
  });

  // xml2js/sax does not expose a parsed doctype node, so its callers screen the
  // raw string with containsDoctype. See https://github.com/ory/polis/issues/4071.
  describe('containsDoctype', function () {
    it('should detect a DOCTYPE declaration', function () {
      assert.strictEqual(containsDoctype('<?xml version="1.0"?><!DOCTYPE r><r/>'), true);
    });

    it('should detect a DOCTYPE with an internal subset', function () {
      assert.strictEqual(
        containsDoctype('<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]><r>&x;</r>'),
        true
      );
    });

    it('should be case-insensitive', function () {
      assert.strictEqual(containsDoctype('<!doctype html>'), true);
    });

    it('should return false for XML without a DOCTYPE', function () {
      assert.strictEqual(containsDoctype('<?xml version="1.0"?><root><a>hi</a></root>'), false);
    });

    it('should ignore <!DOCTYPE inside a comment', function () {
      assert.strictEqual(containsDoctype('<root><!-- <!DOCTYPE example> --><a>hi</a></root>'), false);
    });

    it('should ignore <!DOCTYPE inside a CDATA section', function () {
      assert.strictEqual(
        containsDoctype('<root><AttributeValue><![CDATA[<!DOCTYPE example>]]></AttributeValue></root>'),
        false
      );
    });

    it('should still detect a real DOCTYPE that follows a comment', function () {
      assert.strictEqual(containsDoctype('<!-- a comment --><!DOCTYPE r><r/>'), true);
    });
  });

  describe('thumbprint', function () {
    it('should calculate correct thumbprint', function () {
      const cert =
        'MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==';
      // Expected thumbprint for this cert
      const expected = 'e606eced42fa3abd0c5693456384f5931b174707';
      assert.strictEqual(thumbprint(cert), expected);
    });
  });

  describe('getAttribute', function () {
    const obj = {
      a: {
        b: {
          c: 'value',
        },
      },
    };

    it('should retrieve nested attributes', function () {
      assert.strictEqual(getAttribute(obj, 'a.b.c'), 'value');
    });

    it('should return default value if attribute missing', function () {
      assert.strictEqual(getAttribute(obj, 'a.b.d', 'default'), 'default');
    });

    it('should return default value if path is invalid', function () {
      assert.strictEqual(getAttribute(obj, 'x.y.z', 'default'), 'default');
    });
  });

  describe('isMultiRootedXMLError', function () {
    it('should return true for multi-rooted error message', function () {
      const err = { message: 'Only one element can be added and only after doctype' };
      assert.strictEqual(isMultiRootedXMLError(err), true);
    });

    it('should return false for other errors', function () {
      const err = { message: 'Other error' };
      assert.strictEqual(isMultiRootedXMLError(err), false);
    });
  });
});
