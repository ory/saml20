import { SAMLProfile, SAMLResponseOptions } from './typings';
import xml2js from 'xml2js';
import xmlbuilder from 'xmlbuilder';
import crypto from 'crypto';
import { getVersion } from './getVersion';
import { validateSignature, sanitizeXML } from './validateSignature';
import { decryptXml } from './decrypt';
import { select } from 'xpath';
import saml20 from './saml20';
import { parseFromString, isMultiRootedXMLError, multiRootedXMLError, generateUniqueID } from './utils';
import { sign } from './sign';
import { encryptAssertion, EncryptionAlgorithms } from './encrypt';

const nameFormatUri = [
  'urn:oid:0.9.2342.19200300.100.1.1',
  'urn:oid:0.9.2342.19200300.100.1.3',
  'urn:oid:2.5.4.42',
  'urn:oid:2.5.4.4',
  'urn:oid:2.5.4.12',
  'urn:oid:0.9.2342.19200300.100.1.60',
  'urn:mace:dir:attribute-def:uid',
  'urn:mace:dir:attribute-def:mail',
  'urn:mace:dir:attribute-def:givenName',
  'urn:mace:dir:attribute-def:sn',
  'urn:mace:dir:attribute-def:title',
  'urn:mace:dir:attribute-def:jpegPhoto',
];

const tokenHandlers = {
  '2.0': saml20,
};

class WrapError extends Error {
  inner?: any;
}

/**@deprecated Use parseIssuer instead */
const parse = async (rawAssertion: string): Promise<SAMLProfile> => {
  return new Promise((resolve, reject) => {
    parseInternal(rawAssertion, function onParse(err: Error, profile: SAMLProfile) {
      if (err) {
        reject(err);
        return;
      }
      resolve(profile);
    });
  });
};

const validate = async (rawAssertion: string, options): Promise<SAMLProfile> => {
  return new Promise((resolve, reject) => {
    validateInternal(rawAssertion, options, function onValidate(err, profile: SAMLProfile) {
      if (err) {
        reject(err);
        return;
      }
      resolve(profile);
    });
  });
};

const parseInternal = async (rawAssertion, cb) => {
  if (!rawAssertion) {
    cb(new Error('rawAssertion is required.'));
    return;
  }
  // Save the js object derived from xml and check status code
  const assertionObj = await xmlToJs(rawAssertion, cb);

  checkStatusCode(assertionObj, cb);

  parseResponseAndVersion(assertionObj, assertionObj, function onParse(err, assertion, version) {
    if (err) {
      cb(err);
      return;
    }

    parseAttributes(assertion, tokenHandlers[version], cb);
  });
};

const parseIssuer = (rawAssertion) => {
  if (!rawAssertion) {
    throw new Error('rawAssertion is required.');
  }

  const xml = parseFromString(rawAssertion);

  const issuerValue = select(
    "/*[contains(local-name(), 'Response')]/*[local-name(.)='Issuer']",
    // @ts-expect-error missing Node properties are not needed
    xml!
  ) as Node[];
  if (issuerValue && issuerValue.length > 0) {
    return issuerValue[0].textContent?.toString();
  }
};

const validateInternal = async (rawAssertion, options, cb) => {
  const originalAssertion = rawAssertion;
  if (!rawAssertion) {
    cb(new Error('rawAssertion is required.'));
    return;
  }

  if (!options || (!options.publicKey && !options.thumbprint)) {
    cb(new Error('publicKey or thumbprint are options required.'));
    return;
  }

  if (options.publicKey && options.thumbprint) {
    cb(new Error('You should provide either cert or certThumbprint, not both'));
    return;
  }

  let decAssertion = false;
  try {
    const { assertion, decrypted } = decryptXml(rawAssertion, options);
    rawAssertion = assertion;
    decAssertion = decrypted;
  } catch (err) {
    if (isMultiRootedXMLError(err)) {
      cb(multiRootedXMLError);
      return;
    }
    cb(err);
    return;
  }

  // rawAssertion is our SAML Response. However, we still call it rawAssertion because of legacy naming convention
  const responseObj = await xmlToJs(rawAssertion, cb);
  checkStatusCode(responseObj, cb);

  let signedXml: string | null;

  try {
    signedXml = validateSignature(rawAssertion, options.publicKey, options.thumbprint);
  } catch (e) {
    const error = new WrapError('Invalid assertion.');
    error.inner = e;
    cb(error);
    return;
  }

  if (decAssertion && !signedXml) {
    // try the fallback verification where signature has been generated on the encrypted SAML by some IdPs (like OpenAthens)
    try {
      signedXml = validateSignature(originalAssertion, options.publicKey, options.thumbprint);
    } catch (e) {
      const error = new WrapError('Invalid assertion.');
      error.inner = e;
      cb(error);
    }
  }

  if (!signedXml) {
    cb(new Error('Invalid assertion signature.'));
    return;
  }

  // signedXml is either: Assertion or Response XML
  // in the case of Response XML, we have to handle the Responses with the encrypted SAML Responses
  // so let's use the previous helper function to decrypt response once again (if it is one)
  // if no decryption occured, then decryptedSignedXml is just signedXml
  const { assertion: decryptedSignedXml } = decryptXml(signedXml, options);

  // Save the js object derived from xml and check status code
  const assertionObj = await xmlToJs(decryptedSignedXml, cb); // this is our assertion object

  parseResponseAndVersion(assertionObj, responseObj, function onParse(err, assertion, version) {
    if (err) {
      cb(err);
      return;
    }

    const tokenHandler = tokenHandlers[version];

    if (!options.bypassExpiration && !tokenHandler.validateExpiration(assertion)) {
      cb(new Error('Assertion is expired.'));
      return;
    }

    if (options.audience && !tokenHandler.validateAudience(assertion, options.audience)) {
      cb(new Error('Invalid audience.'));
      return;
    }

    if (options.inResponseTo && assertion.inResponseTo && assertion.inResponseTo !== options.inResponseTo) {
      cb(new Error('Invalid InResponseTo.'));
      return;
    }

    parseAttributes(assertion, tokenHandler, cb);
  });
};

const xmlToJs = async (rawAssertion, cb) => {
  try {
    rawAssertion = sanitizeXML(rawAssertion);
    const parser = new xml2js.Parser({
      attrkey: '@',
      charkey: '_',
      tagNameProcessors: [xml2js.processors.stripPrefix],
    });

    const jsObj = await parser.parseStringPromise(rawAssertion);
    return flattenObject(jsObj);
  } catch (err) {
    const error = new WrapError('An error occurred trying to parse XML assertion.');
    error.inner = err;
    cb(error);
  }
};

const checkStatusCode = (responseObj, cb) => {
  const statusValue =
    responseObj.Response &&
    responseObj.Response.Status &&
    responseObj.Response.Status.StatusCode &&
    responseObj.Response.Status.StatusCode['@'] &&
    responseObj.Response.Status.StatusCode['@'].Value;
  const statusParts = statusValue ? statusValue.split(':') : statusValue;
  const status = statusParts
    ? statusParts.length > 0
      ? statusParts[statusParts.length - 1]
      : undefined
    : undefined;

  if (status && status !== 'Success') {
    cb(new Error(`Invalid Status Code (${status}).`));
  }
};

/*
  Assertion Object: either a SAML Response or a SAML Assertion
  Response Object: the SAML Response. We want to isolate the two because assertionObj may be signed
  but the responseObj is unsigned
 */

function parseResponseAndVersion(assertionObj, responseObj, cb) {
  let assertion =
    assertionObj.Assertion ||
    (assertionObj.Response && assertionObj.Response.Assertion) ||
    (assertionObj.RequestSecurityTokenResponse &&
      assertionObj.RequestSecurityTokenResponse.RequestedSecurityToken &&
      assertionObj.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion);
  // if we have an array of assertions then pick first element
  if (assertion && assertion[0]) {
    assertion = assertion[0];
  }

  if (!assertion) {
    cb(new Error('Invalid assertion.'));
    return;
  }

  const version = getVersion(assertion);
  const response = responseObj;

  if (!version) {
    cb(new Error('SAML Assertion version not supported.'));
    return;
  }

  const tokenHandler = tokenHandlers[version];
  assertion.inResponseTo = tokenHandler.getInResponseTo(responseObj);

  cb(null, assertion, version, response);
}

function flattenObject(obj) {
  Object.keys(obj).forEach(function objectForEach(key) {
    if (obj[key] && obj[key][0] && obj[key].length === 1) {
      obj[key] = obj[key][0];
    }

    if (typeof obj[key] === 'object') {
      return flattenObject(obj[key]);
    }
  });

  return obj;
}

function parseAttributes(assertion, tokenHandler, cb) {
  let profile = null;

  try {
    profile = tokenHandler.parse(assertion);
  } catch (e) {
    const error = new WrapError('An error occurred trying to parse assertion.');
    error.inner = e;

    cb(error);
    return;
  }

  cb(null, profile);
}

const flattenedArray = (arr: string[]) => {
  const escArr = arr.map((val) => {
    return val.replace(/,/g, '%2C');
  });
  return [escArr.join(',')];
};

const nameFormat = (attributeName: string) => {
  if (nameFormatUri.includes(attributeName)) {
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
  }

  return 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
};
// Create SAML Response and sign it
const createSAMLResponse = async (options: SAMLResponseOptions): Promise<string> => {
  const {
    audience,
    issuer,
    acsUrl,
    claims,
    signingKey,
    publicKey,
    flattenArray = false,
    ttlInMinutes = 10,
    encryptionKey,
    encryptionAlgorithm,
    signResponse,
  } = options;

  const requestId = options.requestId || generateUniqueID();
  const responseId = generateUniqueID();
  const assertionId = generateUniqueID();

  const now = new Date();
  const authTimestamp = now.toISOString();

  const notBeforeDate = new Date(now.getTime());
  notBeforeDate.setMinutes(notBeforeDate.getMinutes() - 5);
  const notBefore = notBeforeDate.toISOString();

  const notAfterDate = new Date(now.getTime());
  notAfterDate.setMinutes(notAfterDate.getMinutes() + ttlInMinutes);
  const notAfter = notAfterDate.toISOString();

  const assertionNodes = {
    'saml:Assertion': {
      '@ID': assertionId,
      '@IssueInstant': authTimestamp,
      '@Version': '2.0',
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      '@xmlns:xs': 'http://www.w3.org/2001/XMLSchema',
      'saml:Issuer': {
        '@Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': issuer,
      },
      'saml:Subject': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'saml:NameID': {
          '@Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
          '#text': claims.email,
        },
        'saml:SubjectConfirmation': {
          '@Method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
          'saml:SubjectConfirmationData': {
            '@InResponseTo': requestId,
            '@NotOnOrAfter': notAfter,
            '@Recipient': acsUrl,
          },
        },
      },
      'saml:Conditions': {
        '@NotBefore': notBefore,
        '@NotOnOrAfter': notAfter,
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'saml:AudienceRestriction': {
          'saml:Audience': {
            '#text': audience,
          },
        },
      },
      'saml:AuthnStatement': {
        '@AuthnInstant': authTimestamp,
        '@SessionIndex': requestId,
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'saml:AuthnContext': {
          'saml:AuthnContextClassRef': {
            '#text': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
          },
        },
      },
      'saml:AttributeStatement': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'saml:Attribute': Object.keys(claims.raw || {}).map((attributeName) => {
          const attributeValue = claims.raw[attributeName];
          const attributeValueArray = Array.isArray(attributeValue)
            ? flattenArray
              ? flattenedArray(attributeValue)
              : attributeValue
            : [attributeValue];

          return {
            '@Name': attributeName,
            '@NameFormat': nameFormat(attributeName),
            'saml:AttributeValue': attributeValueArray.map((value: any) => {
              return {
                '@xmlns:xs': 'http://www.w3.org/2001/XMLSchema',
                '@xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                '@xsi:type': 'xs:string',
                '#text': value,
              };
            }),
          };
        }),
      },
    },
  };

  let assertionXml = xmlbuilder.create(assertionNodes, { encoding: 'UTF-8' }).end();

  if (signingKey) {
    assertionXml = sign(assertionXml, {
      privateKey: signingKey,
      publicKey,
      sigLocation: `//*[@ID="${assertionId}"]`,
    });
  }

  if (encryptionKey) {
    try {
      assertionXml = await encryptAssertion(assertionXml, {
        publicKey: encryptionKey,
        encryptionAlgorithm: encryptionAlgorithm || EncryptionAlgorithms.AES256_CBC
      });
    } catch (error: any) {
      throw new Error(`SAML Assertion encryption failed: ${error.message}`);
    }
  }

  const responseNodes = {
    'samlp:Response': {
      '@Destination': acsUrl,
      '@ID': responseId,
      '@InResponseTo': requestId,
      '@IssueInstant': authTimestamp,
      '@Version': '2.0',
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@xmlns:xs': 'http://www.w3.org/2001/XMLSchema',
      'saml:Issuer': {
        '@Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': issuer,
      },
      'samlp:Status': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'samlp:StatusCode': {
          '@Value': 'urn:oasis:names:tc:SAML:2.0:status:Success',
        },
      },
    },
  };

  const responseBuilder = xmlbuilder.create(responseNodes, { encoding: 'UTF-8', standalone: false });

  responseBuilder.root().raw(assertionXml);

  let finalResponseXml = responseBuilder.end({ pretty: true });

  if (signResponse && signingKey) {
    finalResponseXml = sign(finalResponseXml, {
      privateKey: signingKey,
      publicKey,
      sigLocation: `//*[@ID="${responseId}"]`,
    });
  }

  return finalResponseXml;
};

export { createSAMLResponse, parse, validate, parseIssuer, WrapError };
