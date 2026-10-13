import assert from 'assert';
import { parseIssuer, validate, createSAMLResponse, WrapError } from '../../lib/response';
import type { ValidateOptions } from '../../lib/typings';
import { doctypeNotAllowedError } from '../../lib/utils';
import saml20 from '../../lib/saml20';
import fs from 'fs';
import { SignedXml } from 'xml-crypto';
import {
  ACS,
  ASSERTION_NS,
  ASSERTION_XPATH,
  IDP,
  PROTOCOL_NS,
  REQUEST_ID,
  RESPONSE_XPATH,
  SP,
  buildAssertion,
  buildResponse,
  encryptAssertion,
  signXml,
  testIdpCert,
  testIdpKey,
} from '../helpers/fixtures';

const rawResponse = fs.readFileSync('./test/assets/saml20.validResponseSignedMessage.xml').toString();
const rawResponseAuthnFailed = fs
  .readFileSync('./test/assets/saml20.validResponseSignedMessageInvalidStatusCode.xml')
  .toString();
const validateOpts = {
  thumbprint: 'e606eced42fa3abd0c5693456384f5931b174707',
  audience: 'http://sp.example.com/demo1/metadata.php',
  inResponseTo: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
};
const errorResponse = fs.readFileSync('./test/assets/saml20.errorResponse.xml').toString();
const validResponse = fs.readFileSync('./test/assets/saml20.validResponse.xml').toString();
const certificate =
  'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5BcFe0ssmeKTAJBgUrDgMCHQUAMB8xHTAbBgNVBAMTFGlkZW50aXR5LmtpZG96ZW4uY29tMB4XDTEyMDcwNTE4NTEzNFoXDTM5MTIzMTIzNTk1OVowHzEdMBsGA1UEAxMUaWRlbnRpdHkua2lkb3plbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ1GPvzmIZ5OO5by9Qn2fsSuLIJWHfewRzgxcZ6SykzmjD4H1aGOtjUg5EFgQ/HWxa16oJ+afWa0dyeXAiLl5gas71FzgzeODL1STIuyLXFVLQvIJX/HTQU+qcMBlwsscdvVaJSYQsI3OC8Ny5GZvt1Jj2G9TzMTg2hLk5OfO1zxAgMBAAGjVDBSMFAGA1UdAQRJMEeAEDSvlNc0zNIzPd7NykB3GAWhITAfMR0wGwYDVQQDExRpZGVudGl0eS5raWRvemVuLmNvbYIQVWXAvbbQyI5BcFe0ssmeKTAJBgUrDgMCHQUAA4GBAIMmDNzL+Kl5omgxKRTgNWMSZAaMLgAo2GVnZyQ26mc3v+sNHRUJYJzdYOpU6l/P2d9YnijDz7VKfOQzsPu5lHK5s0NiKPaSb07wJBWCNe3iwuUNZg2xg/szhiNSWdq93vKJG1mmeiJSuMlMafJVqxC6K5atypwNNBKbpJEj4w5+';
const inResponseTo = 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685';
const issuerName = 'https://identity.kidozen.com/';
const audience = 'http://demoscope.com';
const suffixAudience = 'http://demoscope';
const validToken = fs.readFileSync('./test/assets/saml20.validToken.xml').toString();
const invalidToken = fs.readFileSync('./test/assets/saml20.invalidToken.xml').toString();
const invalidWrappedToken = fs.readFileSync('./test/assets/saml20.invalidWrappedToken.xml').toString();

const testIdpPublicKey = fs.readFileSync('./test/assets/certificates/testIdpCert.crt').toString();
const testIdpPrivateKey = fs.readFileSync('./test/assets/certificates/testIdpKey.pem').toString();

describe('response.ts', function () {
  it('rejects a response with an unsuccessful StatusCode', async function () {
    await assert.rejects(validate(rawResponseAuthnFailed, validateOpts), {
      message: 'Invalid Status Code (AuthnFailed).',
    });
  });

  it('rejects a response that is not XML', async function () {
    await assert.rejects(validate('rawResponse', validateOpts), { message: 'missing root element' });
  });

  // See https://github.com/ory/polis/issues/4071.
  it('rejects a response with a DTD', async function () {
    const dtdResponse =
      '<?xml version="1.0"?>\n' +
      '<!DOCTYPE foo [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>\n' +
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&x;</samlp:Response>';
    await assert.rejects(validate(dtdResponse, validateOpts), doctypeNotAllowedError);
  });

  // Rejecting the DTD must not leave a detached async continuation that
  // dereferences undefined and crashes the process. See ory/polis#4071.
  it('should not emit an unhandled rejection when validate() rejects a DTD', async function () {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      await assert.rejects(
        validate('<!DOCTYPE foo [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]><root>ok</root>', validateOpts)
      );
      // Let any detached continuation settle before asserting.
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepStrictEqual(unhandled, [], 'no detached unhandled rejection');
    } finally {
      process.removeListener('unhandledRejection', onUnhandled);
    }
  });

  it('rejects an error response that has no assertion', async function () {
    await assert.rejects(validate(errorResponse, { audience: SP, publicKey: testIdpCert }), {
      message: 'Invalid Status Code (AuthnFailed).',
    });
  });

  it('validate ok', async function () {
    const response = await validate(rawResponse, { ...validateOpts, bypassExpiration: true });
    assert.strictEqual(response.audience, 'http://sp.example.com/demo1/metadata.php');
    assert.strictEqual(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
      '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7'
    );
    assert.strictEqual(response.issuer, 'http://idp.example.com/metadata.php');
  });

  it('validate raw response with invalid StatusCode', async function () {
    await assert.rejects(validate(rawResponseAuthnFailed, validateOpts), {
      message: 'Invalid Status Code (AuthnFailed).',
    });
  });

  it('validate stops at a non-Success StatusCode before running the replay validator', async function () {
    const samlResponse = await createSAMLResponse({
      audience: 'http://sp.example.com/demo1/metadata.php',
      issuer: 'http://idp.example.com/metadata.php',
      acsUrl: 'http://sp.example.com/demo1/index.php?acs',
      claims: { email: 'jackson@example.com', raw: {} },
      requestId: inResponseTo,
      privateKey: testIdpPrivateKey,
      publicKey: testIdpPublicKey,
    });
    // The assertion keeps its valid signature (it is verified first); only the
    // Response status changes.
    const failedResponse = samlResponse.replace(
      'urn:oasis:names:tc:SAML:2.0:status:Success',
      'urn:oasis:names:tc:SAML:2.0:status:Responder'
    );
    assert.notStrictEqual(failedResponse, samlResponse);

    let replayValidatorCalls = 0;
    await assert.rejects(
      validate(failedResponse, {
        publicKey: testIdpPublicKey,
        audience: 'http://sp.example.com/demo1/metadata.php',
        assertionReplayValidator: () => {
          replayValidatorCalls++;
          return false;
        },
      }),
      { message: 'Invalid Status Code (Responder).' }
    );
    // Before the fix, validation kept running after the rejection and reached the
    // replay validator a few event-loop turns later; give it time to do so.
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.strictEqual(replayValidatorCalls, 0);
  });

  it('validate raw response not ok', async function () {
    try {
      await validate('rawResponse', validateOpts);
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'missing root element');
    }
  });

  it('Should fail which has no assertion', async function () {
    try {
      await validate(validResponse, {
        audience: validateOpts.audience,
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid assertion.');
    }
  });

  it('Should fail which has no publicKey or thumbprint', async function () {
    try {
      await validate(validResponse, {
        audience: validateOpts.audience,
        publicKey: undefined,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'publicKey or thumbprint are options required.');
    }
  });
  it('Assertion is expired.', async function () {
    try {
      validate('invalid-assertion', {
        audience,
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid assertion.');
    }
  });

  it('Should validate saml 2.0 token using certificate', async function () {
    const response = await validate(validToken, { audience, publicKey: certificate, bypassExpiration: true });
    assert.strictEqual(response.issuer, issuerName);
    assert.strictEqual(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
      'demo@kidozen.com'
    );
  });

  it('Should validate saml 2.0 token and check audience', async function () {
    const response = await validate(validToken, {
      publicKey: certificate,
      audience: audience,
      bypassExpiration: true,
    });
    assert.strictEqual(response.audience, audience);
  });

  it('Should reject saml 2.0 token when the expected audience is only a prefix', async function () {
    await assert.rejects(
      validate(validToken, { publicKey: certificate, audience: suffixAudience, bypassExpiration: true }),
      { message: 'Invalid audience.' }
    );
  });

  it('Should fail with invalid audience', async function () {
    try {
      await validate(validToken, {
        publicKey: certificate,
        audience: 'http://any-other-audience.com/',
        bypassExpiration: true,
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid audience.');
    }
  });
  it('Should fail with invalid signature', async function () {
    try {
      await validate(invalidToken, { audience, publicKey: certificate, bypassExpiration: true });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid assertion signature.');
    }
  });

  it('Should fail with missing root element', async function () {
    try {
      await validate('invalid-assertion', { audience, publicKey: certificate, bypassExpiration: true });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'missing root element');
    }
  });

  it('Should fail with invalid assertion and possible assertion wrapping', async function () {
    try {
      await validate(invalidWrappedToken, { audience, publicKey: certificate, bypassExpiration: true });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid assertion. Possible assertion wrapping.');
    }
  });

  it('Should fail with expired assertion', async function () {
    try {
      await validate(validToken, { audience, publicKey: certificate });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Assertion is expired.');
    }
  });

  it('parseIssuer response ok', async function () {
    const issuer = await parseIssuer(validResponse);
    assert.strictEqual(issuer, 'http://idp.example.com/metadata.php');
  });

  it('parseIssuer not ok', async function () {
    try {
      await parseIssuer('rawResponse');
    } catch (error) {
      assert.strictEqual((error as Error).message, 'missing root element');
    }
  });

  it('maps a persistent NameID attribute value to the nameidentifier claim', async function () {
    const response = signXml(
      buildResponse(
        buildAssertion({
          attributes:
            '<saml:AttributeStatement><saml:Attribute Name="urn:oid:abcd.3"><saml:AttributeValue>' +
            '<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">permanent-id</saml:NameID>' +
            '</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>',
        })
      ),
      RESPONSE_XPATH
    );
    const profile = await validate(response, { audience: SP, publicKey: testIdpCert });
    assert.strictEqual(
      profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
      'permanent-id'
    );
  });

  it('Should create a SAML response', async function () {
    const json = {
      audience: 'http://sp.example.com/demo1/metadata.php',
      issuer: 'http://idp.example.com/metadata.php',
      acsUrl: 'http://sp.example.com/demo1/index.php?acs',
      claims: {
        raw: {
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier':
            '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7',
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'jackson@example.com',
          groups: ['admin,owner', 'user'],
        },
      },
      requestId: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
      privateKey: testIdpPrivateKey,
      publicKey: testIdpPublicKey,
    };

    const response = await createSAMLResponse(json);

    const parsed = await validate(response, { audience: json.audience, publicKey: testIdpPublicKey });

    assert.strictEqual(parsed.issuer, json.issuer);
    assert.strictEqual(parsed.audience, json.audience);
    assert.strictEqual(parsed.sessionIndex, json.requestId);
    assert.deepStrictEqual(parsed.claims, json.claims.raw);
  });

  it('Should create a SAML response, flattenArray=true', async function () {
    const json = {
      audience: 'http://sp.example.com/demo1/metadata.php',
      issuer: 'http://idp.example.com/metadata.php',
      acsUrl: 'http://sp.example.com/demo1/index.php?acs',
      claims: {
        raw: {
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier':
            '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7',
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'jackson@example.com',
          groups: ['admin,owner', 'user'],
        },
      },
      requestId: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
      privateKey: testIdpPrivateKey,
      publicKey: testIdpPublicKey,
      flattenArray: true,
    };

    const response = await createSAMLResponse(json);

    const parsed = await validate(response, { audience: json.audience, publicKey: testIdpPublicKey });

    assert.strictEqual(parsed.issuer, json.issuer);
    assert.strictEqual(parsed.audience, json.audience);
    assert.strictEqual(parsed.sessionIndex, json.requestId);
    assert.deepStrictEqual(parsed.claims, { ...json.claims.raw, groups: 'admin%2Cowner,user' });
  });

  it('Should create a SAML response with the given SessionIndex', async function () {
    const json = {
      audience: 'http://sp.example.com/demo1/metadata.php',
      issuer: 'http://idp.example.com/metadata.php',
      acsUrl: 'http://sp.example.com/demo1/index.php?acs',
      claims: {
        raw: {
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'jackson@example.com',
        },
      },
      requestId: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
      privateKey: testIdpPrivateKey,
      publicKey: testIdpPublicKey,
      sessionIndex: '_session-index-from-the-idp',
    };

    const parsed = await validate(await createSAMLResponse(json), {
      audience: json.audience,
      publicKey: testIdpPublicKey,
    });

    assert.strictEqual(parsed.sessionIndex, json.sessionIndex);
  });
});
it('parseIssuer should return the correct issuer value', async function () {
  const rawAssertion = fs.readFileSync('./test/assets/saml20.validResponse.xml').toString();
  const issuer = parseIssuer(rawAssertion);
  assert.strictEqual(issuer, 'http://idp.example.com/metadata.php');
});

it('parseIssuer should throw an error if rawAssertion is not provided', async function () {
  try {
    parseIssuer('');
  } catch (error) {
    assert.strictEqual((error as Error).message, 'rawAssertion is required.');
  }
});

it('parseIssuer should return undefined if Issuer element is missing', async function () {
  const rawAssertion = fs.readFileSync('./test/assets/saml20.noIssuerResponse.xml').toString();
  const issuer = parseIssuer(rawAssertion);
  assert.strictEqual(issuer, undefined);
});

it('Should create a SAML response with nameFormat basic', async function () {
  const json = {
    audience: 'http://sp.example.com/demo1/metadata.php',
    issuer: 'http://idp.example.com/metadata.php',
    acsUrl: 'http://sp.example.com/demo1/index.php?acs',
    claims: {
      raw: {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier':
          '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'jackson@example.com',
        groups: ['admin,owner', 'user'],
        'urn:oid:0.9.2342.19200300.100.1.1': 'urn:oid:0.9.2342.19200300.100.1.1',
        'urn:oid:0.9.2342.19200300.100.1.3': 'urn:oid:0.9.2342.19200300.100.1.3',
        'urn:oid:2.5.4.42': 'urn:oid:2.5.4.42',
        'urn:oid:2.5.4.4': 'urn:oid:2.5.4.4',
        'urn:oid:2.5.4.12': 'urn:oid:2.5.4.12',
        'urn:oid:0.9.2342.19200300.100.1.60': 'urn:oid:0.9.2342.19200300.100.1.60',
        'urn:mace:dir:attribute-def:uid': 'urn:mace:dir:attribute-def:uid',
        'urn:mace:dir:attribute-def:mail': 'urn:mace:dir:attribute-def:mail',
        'urn:mace:dir:attribute-def:givenName': 'urn:mace:dir:attribute-def:givenName',
        'urn:mace:dir:attribute-def:sn': 'urn:mace:dir:attribute-def:sn',
        'urn:mace:dir:attribute-def:title': 'urn:mace:dir:attribute-def:title',
        'urn:mace:dir:attribute-def:jpegPhoto': 'urn:mace:dir:attribute-def:jpegPhoto',
      },
    },
    requestId: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
    privateKey: testIdpPrivateKey,
    publicKey: testIdpPublicKey,
  };

  const response = await createSAMLResponse(json);

  assert.strictEqual(
    response.includes(
      '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">jackson@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">admin,owner</saml:AttributeValue><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:oid:0.9.2342.19200300.100.1.1</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:oid:0.9.2342.19200300.100.1.3</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:oid:2.5.4.42</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:oid:2.5.4.4</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:2.5.4.12" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:oid:2.5.4.12</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.60" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:oid:0.9.2342.19200300.100.1.60</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:mace:dir:attribute-def:uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:mace:dir:attribute-def:uid</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:mace:dir:attribute-def:mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:mace:dir:attribute-def:mail</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:mace:dir:attribute-def:givenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:mace:dir:attribute-def:givenName</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:mace:dir:attribute-def:sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:mace:dir:attribute-def:sn</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:mace:dir:attribute-def:title" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:mace:dir:attribute-def:title</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:mace:dir:attribute-def:jpegPhoto" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">urn:mace:dir:attribute-def:jpegPhoto</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
    ),
    true
  );
});

it('validate should throw error if both publicKey and thumbprint are provided', async function () {
  try {
    await validate(validResponse, {
      audience: validateOpts.audience,
      publicKey: certificate,
      thumbprint: 'thumbprint',
    });
  } catch (error) {
    assert.strictEqual(
      (error as Error).message,
      'You should provide either cert or certThumbprint, not both'
    );
  }
});

it('validate should throw error if rawAssertion is empty', async function () {
  try {
    await validate('', { audience: SP, publicKey: certificate });
  } catch (error) {
    assert.strictEqual((error as Error).message, 'rawAssertion is required.');
  }
});

it('Should create a SAML response with default ttlInMinutes', async function () {
  const json = {
    audience: 'http://sp.example.com/demo1/metadata.php',
    issuer: 'http://idp.example.com/metadata.php',
    acsUrl: 'http://sp.example.com/demo1/index.php?acs',
    claims: {
      raw: {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier':
          '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7',
      },
    },
    requestId: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
    privateKey: testIdpPrivateKey,
    publicKey: testIdpPublicKey,
  };

  const response = await createSAMLResponse(json);

  // Extract NotOnOrAfter and NotBefore from the Conditions element
  const notOnOrAfterMatch = response.match(/NotOnOrAfter="([^"]+)"/);
  const notBeforeMatch = response.match(/NotBefore="([^"]+)"/);

  assert.ok(notOnOrAfterMatch, 'NotOnOrAfter attribute should exist');
  assert.ok(notBeforeMatch, 'NotBefore attribute should exist');

  const notOnOrAfter = new Date(notOnOrAfterMatch[1]);
  const notBefore = new Date(notBeforeMatch[1]);

  // The difference should be exactly 10 minutes + 5 minutes for clock skew tolerance
  const diffInMinutes = (notOnOrAfter.getTime() - notBefore.getTime()) / (1000 * 60);
  assert.strictEqual(diffInMinutes, 10 + 5); // Adding 5 minutes for clock skew tolerance
});

it('Should create a SAML response with custom ttlInMinutes', async function () {
  const ttlInMinutes = 30;
  const json = {
    audience: 'http://sp.example.com/demo1/metadata.php',
    issuer: 'http://idp.example.com/metadata.php',
    acsUrl: 'http://sp.example.com/demo1/index.php?acs',
    claims: {
      raw: {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier':
          '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7',
      },
    },
    requestId: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
    privateKey: testIdpPrivateKey,
    publicKey: testIdpPublicKey,
    ttlInMinutes,
  };

  const response = await createSAMLResponse(json);

  // Extract NotOnOrAfter and NotBefore from the Conditions element
  const notOnOrAfterMatch = response.match(/NotOnOrAfter="([^"]+)"/);
  const notBeforeMatch = response.match(/NotBefore="([^"]+)"/);

  assert.ok(notOnOrAfterMatch, 'NotOnOrAfter attribute should exist');
  assert.ok(notBeforeMatch, 'NotBefore attribute should exist');

  const notOnOrAfter = new Date(notOnOrAfterMatch[1]);
  const notBefore = new Date(notBeforeMatch[1]);

  // The difference should be exactly ttlInMinutes
  const diffInMinutes = (notOnOrAfter.getTime() - notBefore.getTime()) / (1000 * 60);
  assert.strictEqual(diffInMinutes, ttlInMinutes + 5); // Adding 5 minutes for clock skew tolerance
});

describe('validate() with an assertion encrypted before the Response was signed', function () {
  // Some IdPs (OpenAthens, for one) sign the Response over the
  // <EncryptedAssertion>, so the signature only verifies against the original,
  // still-encrypted document. validate() falls back to that check.
  let signedEncrypted: string;

  before(async function () {
    signedEncrypted = signXml(buildResponse(await encryptAssertion(buildAssertion())), RESPONSE_XPATH);
  });

  const options = (extra: Record<string, unknown> = {}) => ({
    privateKey: testIdpKey,
    publicKey: testIdpCert,
    audience: SP,
    inResponseTo: REQUEST_ID,
    recipient: ACS,
    ...extra,
  });

  it('accepts it and returns the decrypted profile', async function () {
    const profile = await validate(signedEncrypted, options());
    assert.strictEqual(profile.issuer, IDP);
    assert.strictEqual(profile.audience, SP);
    assert.strictEqual(profile.sessionIndex, '_session-1');
    assert.deepStrictEqual(profile.nameId, {
      value: 'jo@example.com',
      format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    });
    assert.strictEqual(profile.assertionId, '_assertion-1');
    assert.strictEqual(
      profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
      'jo@example.com'
    );
  });

  it('rejects it when the signed Response was tampered with', async function () {
    const tampered = signedEncrypted.replace(
      `Destination="${ACS}"`,
      'Destination="https://evil.example.com/acs"'
    );
    assert.notStrictEqual(tampered, signedEncrypted);
    await assert.rejects(validate(tampered, options()), { message: 'Invalid assertion signature.' });
  });

  it('rejects it when the signing certificate is not trusted', async function () {
    await assert.rejects(validate(signedEncrypted, options({ publicKey: certificate })), /Invalid assertion/);
  });

  it('rejects it when no decryption key is supplied', async function () {
    await assert.rejects(validate(signedEncrypted, options({ privateKey: undefined })), {
      message: 'Exception of Assertion Decryption.',
    });
  });
});

describe('validate() with a WS-Trust RequestSecurityTokenResponse (ADFS over WS-Federation)', function () {
  const rstr = (token: string) =>
    '<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust" Id="_rstr-1">' +
    '<t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    new Date().toISOString() +
    '</wsu:Created></t:Lifetime>' +
    `<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>${SP}</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>` +
    `<t:RequestedSecurityToken>${token}</t:RequestedSecurityToken>` +
    '</t:RequestSecurityTokenResponse>';

  // An enveloped signature over the whole RequestSecurityTokenResponse.
  const signEnvelope = (xml: string) => {
    const sig = new SignedXml({
      privateKey: testIdpKey,
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    });
    sig.addReference({
      xpath: '/*',
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ],
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    });
    sig.computeSignature(xml, { location: { reference: '/*', action: 'append' } });
    return sig.getSignedXml();
  };

  it('accepts a signed Assertion inside an unsigned RequestSecurityTokenResponse', async function () {
    const assertion = signXml(buildAssertion(), ASSERTION_XPATH).replace(/^<\?xml[^>]*>/, '');
    const profile = await validate(rstr(assertion), { publicKey: testIdpCert, audience: SP });
    assert.strictEqual(profile.issuer, IDP);
    assert.strictEqual(profile.assertionId, '_assertion-1');
  });

  it('accepts an Assertion inside a signed RequestSecurityTokenResponse', async function () {
    const profile = await validate(signEnvelope(rstr(buildAssertion())), {
      publicKey: testIdpCert,
      audience: SP,
    });
    assert.strictEqual(profile.issuer, IDP);
    assert.strictEqual(profile.assertionId, '_assertion-1');
  });

  it('rejects a signed RequestSecurityTokenResponse whose Assertion was changed', async function () {
    const tampered = signEnvelope(rstr(buildAssertion())).replace('jo@example.com', 'eve@example.com');
    await assert.rejects(validate(tampered, { publicKey: testIdpCert, audience: SP }), {
      message: 'Invalid assertion signature.',
    });
  });

  it('runs the usual checks on the Assertion inside a signed RequestSecurityTokenResponse', async function () {
    await assert.rejects(
      validate(signEnvelope(rstr(buildAssertion())), {
        publicKey: testIdpCert,
        audience: 'https://other.example.com',
      }),
      { message: 'Invalid audience.' }
    );
  });
});

describe('validate() edge cases', function () {
  it('uses the first Assertion when a signed Response carries several', async function () {
    const response = signXml(
      buildResponse(buildAssertion({ id: '_first' }) + buildAssertion({ id: '_second' })),
      RESPONSE_XPATH
    );
    const profile = await validate(response, { publicKey: testIdpCert, audience: SP });
    assert.strictEqual(profile.assertionId, '_first');
  });

  // validate() parses the document once before sanitizeXML strips &#xd; and
  // once after, so the second parse must catch a DTD keyword it assembles.
  it('rejects a DTD keyword that sanitizeXML assembles', async function () {
    for (const inner of ['<!-- <!DOC&#xd;TYPE x> -->', '<![CDATA[<!EN&#xD;TITY x>]]>']) {
      await assert.rejects(
        validate(buildResponse(inner), { publicKey: testIdpCert, audience: SP }),
        (error: WrapError) => {
          assert.strictEqual(error.message, 'An error occurred trying to parse XML assertion.');
          assert.strictEqual(error.inner, doctypeNotAllowedError);
          return true;
        }
      );
    }
  });

  it('rejects a signed Response without an Assertion', async function () {
    await assert.rejects(
      validate(signXml(buildResponse(''), RESPONSE_XPATH), { publicKey: testIdpCert, audience: SP }),
      {
        message: 'Invalid assertion.',
      }
    );
  });

  it('rejects a signed Assertion that has no Version', async function () {
    const response = signXml(
      `<samlp:Response xmlns:samlp="${PROTOCOL_NS}" xmlns:saml="${ASSERTION_NS}">` +
        `<saml:Issuer>${IDP}</saml:Issuer>` +
        `<saml:Assertion><saml:Issuer>${IDP}</saml:Issuer></saml:Assertion></samlp:Response>`,
      RESPONSE_XPATH
    );
    await assert.rejects(validate(response, { audience: SP, publicKey: testIdpCert }), {
      message: 'SAML Assertion version not supported.',
    });
  });

  it('wraps a failure while reading attributes', async function () {
    // An <Attribute> without a Name has no attributes at all, so reading its
    // Name throws inside the claims parser.
    const response = signXml(
      buildResponse(
        buildAssertion({
          attributes:
            '<saml:AttributeStatement><saml:Attribute><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>',
        })
      ),
      RESPONSE_XPATH
    );
    await assert.rejects(validate(response, { audience: SP, publicKey: testIdpCert }), (error: WrapError) => {
      assert(error instanceof WrapError);
      assert.strictEqual(error.message, 'An error occurred trying to parse assertion.');
      assert(error.inner instanceof Error);
      return true;
    });
  });
});

describe('validate() requires an audience', function () {
  const signed = () => signXml(buildResponse(buildAssertion()), RESPONSE_XPATH);
  const missing: [string, unknown][] = [
    ['omitted', undefined],
    ['an empty string', ''],
    ['an empty list', []],
    ['a list with an empty string', [SP, '']],
    ['not a string', 42],
  ];

  for (const [name, audience] of missing) {
    it(`rejects an audience that is ${name}`, async function () {
      await assert.rejects(
        validate(signed(), { publicKey: testIdpCert, audience } as unknown as ValidateOptions),
        { message: 'audience is required.' }
      );
    });
  }
});

describe('validate() matches audiences exactly', function () {
  const signedFor = (audience: string) =>
    signXml(buildResponse(buildAssertion({ audienceRestrictions: [[audience]] })), RESPONSE_XPATH);

  it('accepts an assertion whose Audience equals the expected one', async function () {
    const profile = await validate(signedFor(SP), { publicKey: testIdpCert, audience: SP });
    assert.strictEqual(profile.audience, SP);
  });

  // A prefix match let an assertion issued for https://sp.example.com/metadata.evil.example
  // pass as one for https://sp.example.com/metadata.
  it('rejects an assertion whose Audience only starts with the expected one', async function () {
    await assert.rejects(
      validate(signedFor(`${SP}.evil.example`), { publicKey: testIdpCert, audience: SP }),
      {
        message: 'Invalid audience.',
      }
    );
  });

  it('rejects an assertion whose Audience is a prefix of the expected one', async function () {
    await assert.rejects(
      validate(signedFor('https://sp.example.com'), { publicKey: testIdpCert, audience: SP }),
      { message: 'Invalid audience.' }
    );
  });

  it('rejects an expected audience that is a prefix of one in a list', async function () {
    await assert.rejects(
      validate(signedFor(`${SP}/x`), { publicKey: testIdpCert, audience: ['https://z.example.com', SP] }),
      { message: 'Invalid audience.' }
    );
  });
});

describe('validate() audience checks on signed responses', function () {
  const signedWith = (audienceRestrictions: string[][]) =>
    signXml(buildResponse(buildAssertion({ audienceRestrictions })), RESPONSE_XPATH);
  const options = { publicKey: testIdpCert, audience: SP };

  it('accepts an assertion that lists the SP among several audiences', async function () {
    const profile = await validate(signedWith([['https://other.example.com', SP]]), options);
    assert.strictEqual(profile.issuer, IDP);
    assert.strictEqual(profile.audience, 'https://other.example.com');
    assert.deepStrictEqual(profile.audiences, ['https://other.example.com', SP]);
  });

  it('returns the audience of an assertion with a single Audience', async function () {
    const profile = await validate(signedWith([[SP]]), options);
    assert.strictEqual(profile.audience, SP);
    assert.deepStrictEqual(profile.audiences, [SP]);
  });

  it('rejects an assertion whose audiences do not include the SP', async function () {
    await assert.rejects(
      validate(signedWith([['https://a.example.com', 'https://b.example.com']]), options),
      {
        message: 'Invalid audience.',
      }
    );
  });

  it('requires every AudienceRestriction to name the SP', async function () {
    const profile = await validate(signedWith([[SP], ['https://other.example.com', SP]]), options);
    assert.strictEqual(profile.issuer, IDP);
    assert.strictEqual(profile.audience, SP);
    assert.deepStrictEqual(profile.audiences, [SP, 'https://other.example.com', SP]);
    await assert.rejects(validate(signedWith([[SP], ['https://other.example.com']]), options), {
      message: 'Invalid audience.',
    });
  });
});

describe('validate() on an unsigned response', function () {
  it('rejects it and keeps the reason in inner', async function () {
    await assert.rejects(
      validate(buildResponse(buildAssertion()), { audience: SP, publicKey: testIdpCert }),
      (error: WrapError) => {
        assert.strictEqual(error.message, 'Invalid assertion.');
        assert.strictEqual(error.inner.message, 'invalid signature: no Signature element found');
        return true;
      }
    );
  });
});

describe('validate() error handling', function () {
  const signedResponse = () => signXml(buildResponse(buildAssertion()), RESPONSE_XPATH);

  it('wraps an unexpected failure inside the assertion checks', async function () {
    const original = saml20.validateExpiration;
    saml20.validateExpiration = () => {
      throw new Error('boom');
    };
    try {
      await assert.rejects(
        validate(signedResponse(), { audience: SP, publicKey: testIdpCert }),
        (error: WrapError) => {
          assert(error instanceof WrapError);
          assert.strictEqual(error.message, 'An error occurred trying to validate the assertion.');
          assert.strictEqual(error.inner.message, 'boom');
          return true;
        }
      );
    } finally {
      saml20.validateExpiration = original;
    }
  });

  it('wraps a failing replay validator and keeps its error in inner', async function () {
    await assert.rejects(
      validate(signedResponse(), {
        audience: SP,
        publicKey: testIdpCert,
        assertionReplayValidator: async () => {
          throw new Error('store unavailable');
        },
      }),
      (error: WrapError) => {
        assert.strictEqual(error.message, 'An error occurred during assertion replay validation.');
        assert.strictEqual(error.inner.message, 'store unavailable');
        return true;
      }
    );
  });

  it('settles every failure path without an unhandled rejection', async function () {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      const signed = signedResponse();
      const attempts: [string, Record<string, unknown>][] = [
        ['', { publicKey: testIdpCert, audience: SP }],
        [signed, {}],
        [signed, { publicKey: testIdpCert }],
        [signed, { publicKey: testIdpCert, thumbprint: 'x', audience: SP }],
        ['<a><b></a>', { publicKey: testIdpCert, audience: SP }],
        [buildResponse(''), { publicKey: testIdpCert, audience: SP }],
        [buildResponse(buildAssertion()), { publicKey: testIdpCert, audience: SP }],
        [signed.replace('jo@example.com', 'eve@example.com'), { publicKey: testIdpCert, audience: SP }],
        [signed, { publicKey: certificate, audience: SP }],
        [signed, { publicKey: testIdpCert, audience: 'https://other.example.com' }],
        [signed, { publicKey: testIdpCert, audience: SP, inResponseTo: '_other' }],
        [signed, { publicKey: testIdpCert, audience: SP, recipient: 'https://other.example.com/acs' }],
        [signed, { publicKey: testIdpCert, audience: SP, assertionReplayValidator: () => true }],
      ];
      for (const [xml, options] of attempts) {
        await assert.rejects(validate(xml, options as unknown as ValidateOptions));
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
      assert.deepStrictEqual(unhandled, []);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });
});
