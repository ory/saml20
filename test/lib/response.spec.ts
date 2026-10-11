import assert from 'assert';
import { parse, parseIssuer, validate, createSAMLResponse, WrapError } from '../../lib/response';
import { doctypeNotAllowedError } from '../../lib/utils';
import fs from 'fs';
import {
  ACS,
  IDP,
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
const validAssertion = fs.readFileSync('./test/assets/saml20.validAssertion.xml').toString();

const oktaPublicKey = fs.readFileSync('./test/assets/certificates/oktaPublicKey.crt').toString();
const oktaPrivateKey = fs.readFileSync('./test/assets/certificates/oktaPrivateKey.pem').toString();
const testIdpPublicKey = fs.readFileSync('./test/assets/certificates/testIdpCert.crt').toString();
const testIdpPrivateKey = fs.readFileSync('./test/assets/certificates/testIdpKey.pem').toString();

describe('response.ts', function () {
  it('RAW response ok', async function () {
    const response = await parse(rawResponse);
    assert.strictEqual(response.audience, 'http://sp.example.com/demo1/metadata.php');
    assert.strictEqual(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
      '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7'
    );
    assert.strictEqual(response.issuer, 'http://idp.example.com/metadata.php');
  });

  it('RAW response with invalid StatusCode', async function () {
    await assert.rejects(parse(rawResponseAuthnFailed), { message: 'Invalid Status Code (AuthnFailed).' });
  });

  it('RAW response not ok', async function () {
    try {
      await parse('rawResponse');
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'An error occurred trying to parse XML assertion.');
    }
  });

  // xml2js runs on the assertion after xmldom, so it needs its own DTD guard.
  // See https://github.com/ory/polis/issues/4071.
  it('RAW response with a DTD is rejected before xml2js', async function () {
    const dtdResponse =
      '<?xml version="1.0"?>\n' +
      '<!DOCTYPE foo [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>\n' +
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&x;</samlp:Response>';
    await assert.rejects(parse(dtdResponse), (err: Error & { inner?: unknown }) => {
      assert.strictEqual(err.inner, doctypeNotAllowedError);
      return true;
    });
  });

  // Rejecting the DTD must not leave a detached async continuation that
  // dereferences undefined and crashes the process. See ory/polis#4071.
  it('should not emit an unhandled rejection when parse() rejects a DTD', async function () {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      await assert.rejects(
        parse('<!DOCTYPE foo [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]><root>ok</root>')
      );
      // Let any detached continuation settle before asserting.
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepStrictEqual(unhandled, [], 'no detached unhandled rejection');
    } finally {
      process.removeListener('unhandledRejection', onUnhandled);
    }
  });

  it('Should not parse saml 2.0 token which has no assertion', async function () {
    try {
      await parse(errorResponse);
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid Status Code (AuthnFailed).');
    }
  });

  it('An error occurred trying to parse XML assertion.', async function () {
    try {
      await parse('undefined');
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'An error occurred trying to parse XML assertion.');
    }
  });

  it('An error occurred trying to parse assertion', async function () {
    try {
      const response = await parse(validResponse);
      assert.strictEqual(response.audience, 'http://sp.example.com/demo1/metadata.php');
      assert.strictEqual(
        response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
        '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7'
      );
      assert.strictEqual(response.issuer, 'http://idp.example.com/metadata.php');
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'An error occurred trying to parse assertion.');
    }
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
    const response = await validate(validToken, { publicKey: certificate, bypassExpiration: true });
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

  it('Should validate saml 2.0 token and check audience with suffix', async function () {
    const response = await validate(validToken, {
      publicKey: certificate,
      audience: suffixAudience,
      bypassExpiration: true,
    });
    assert.strictEqual(response.audience, audience);
  });

  it('Should validate saml 2.0 token and check strict audience with suffix', async function () {
    try {
      await validate(validToken, {
        publicKey: certificate,
        audience: suffixAudience,
        bypassExpiration: true,
        strictAudienceValidation: true,
      });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid audience.');
    }
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
      await validate(invalidToken, { publicKey: certificate, bypassExpiration: true });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid assertion signature.');
    }
  });

  it('Should fail with missing root element', async function () {
    try {
      await validate('invalid-assertion', { publicKey: certificate, bypassExpiration: true });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'missing root element');
    }
  });

  it('Should fail with invalid assertion and possible assertion wrapping', async function () {
    try {
      await validate(invalidWrappedToken, { publicKey: certificate, bypassExpiration: true });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Invalid assertion. Possible assertion wrapping.');
    }
  });

  it('Should fail with expired assertion', async function () {
    try {
      await validate(validToken, { publicKey: certificate });
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Assertion is expired.');
    }
  });

  it('Should parse saml 2.0 without signature validation', async function () {
    const response = await parse(invalidToken);
    assert.strictEqual(response.issuer, issuerName);
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

  it('Should parse saml 2.0 assertion and check nameidentifier picks up nameid-permanent', async function () {
    const response = await parse(validAssertion);
    assert.strictEqual(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
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
      privateKey: oktaPrivateKey,
      publicKey: oktaPublicKey,
    };

    const response = await createSAMLResponse(json);

    const parsed = await parse(response);

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
      privateKey: oktaPrivateKey,
      publicKey: oktaPublicKey,
      flattenArray: true,
    };

    const response = await createSAMLResponse(json);

    const parsed = await parse(response);

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
      privateKey: oktaPrivateKey,
      publicKey: oktaPublicKey,
      sessionIndex: '_session-index-from-the-idp',
    };

    const parsed = await parse(await createSAMLResponse(json));

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
    privateKey: oktaPrivateKey,
    publicKey: oktaPublicKey,
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
    await validate('', { publicKey: certificate });
  } catch (error) {
    assert.strictEqual((error as Error).message, 'rawAssertion is required.');
  }
});

it('parse should throw error if rawAssertion is empty', async function () {
  try {
    await parse('');
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
    privateKey: oktaPrivateKey,
    publicKey: oktaPublicKey,
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
    privateKey: oktaPrivateKey,
    publicKey: oktaPublicKey,
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

describe('parse() edge cases', function () {
  it('rejects a Response without an Assertion', async function () {
    await assert.rejects(parse(buildResponse('')), { message: 'Invalid assertion.' });
  });

  it('uses the first Assertion when a Response carries several', async function () {
    const response = buildResponse(buildAssertion({ id: '_first' }) + buildAssertion({ id: '_second' }));
    const profile = await parse(response);
    assert.strictEqual(profile.assertionId, '_first');
  });

  it('wraps a failure while reading attributes', async function () {
    // An <Attribute> without a Name has no attributes at all, so reading its
    // Name throws inside the claims parser.
    const response = buildResponse(
      buildAssertion({
        attributes:
          '<saml:AttributeStatement><saml:Attribute><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>',
      })
    );
    await assert.rejects(parse(response), (error: WrapError) => {
      assert(error instanceof WrapError);
      assert.strictEqual(error.message, 'An error occurred trying to parse assertion.');
      assert(error.inner instanceof Error);
      return true;
    });
  });
});

describe('validate() audience checks on signed responses', function () {
  const signedWith = (audienceRestrictions: string[][]) =>
    signXml(buildResponse(buildAssertion({ audienceRestrictions })), RESPONSE_XPATH);
  const options = { publicKey: testIdpCert, audience: SP, strictAudienceValidation: true };

  it('accepts an assertion that lists the SP among several audiences', async function () {
    const profile = await validate(signedWith([['https://other.example.com', SP]]), options);
    assert.strictEqual(profile.issuer, IDP);
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
    await assert.rejects(validate(signedWith([[SP], ['https://other.example.com']]), options), {
      message: 'Invalid audience.',
    });
  });
});

describe('validate() on an unsigned response', function () {
  it('rejects it and keeps the reason in inner', async function () {
    await assert.rejects(
      validate(buildResponse(buildAssertion()), { publicKey: testIdpCert }),
      (error: WrapError) => {
        assert.strictEqual(error.message, 'Invalid assertion.');
        assert.strictEqual(error.inner.message, 'invalid signature: no Signature element found');
        return true;
      }
    );
  });
});
