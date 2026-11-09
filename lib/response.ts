import type { AssertionEncryption, SAMLProfile, ValidateOptions } from './typings';
import { getVersion } from './getVersion';
import { verifySignature, verifyRootSignature, sanitizeXML } from './validateSignature';
import type { ValidateSignatureOptions } from './validateSignature';
import { decryptXml } from './decrypt';
import type { EncryptedResponse } from './decrypt';
import { select } from 'xpath';
import saml20 from './saml20';
import { parseFromString, WrapError, generateId, getAttribute } from './utils';
import { xmlToObject, buildXml } from './xml';
import type { XmlNode, XmlValue } from './xml';
import { sign } from './sign';
import { ASSERTION_NS, PROTOCOL_NS, XML_SCHEMA_INSTANCE_NS, XML_SCHEMA_NS } from './constants';

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

const parseIssuer = (rawAssertion: string) => {
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

const validate = async (rawAssertion: string, options: ValidateOptions): Promise<SAMLProfile> => {
  const originalAssertion = rawAssertion;
  if (!rawAssertion) {
    throw new Error('rawAssertion is required.');
  }

  if (!options || (!options.publicKey && !options.thumbprint)) {
    throw new Error('publicKey or thumbprint are options required.');
  }

  if (options.publicKey && options.thumbprint) {
    throw new Error('You should provide either cert or certThumbprint, not both');
  }

  const audiences: unknown[] = Array.isArray(options.audience) ? options.audience : [options.audience];
  if (
    audiences.length === 0 ||
    !audiences.every((audience) => typeof audience === 'string' && audience !== '')
  ) {
    throw new Error('audience is required.');
  }

  // An empty list or entry would make the check below pass for nothing, or
  // skip it; neither is what a caller who set the option wants.
  if (options.recipient !== undefined) {
    const recipients: unknown[] = Array.isArray(options.recipient)
      ? Array.from(options.recipient)
      : [options.recipient];
    if (
      recipients.length === 0 ||
      !recipients.every((recipient) => typeof recipient === 'string' && recipient !== '')
    ) {
      throw new Error('recipient must be a non-empty URL or a non-empty list of them.');
    }
  }

  // Optional algorithm allowlists and the Reference ceiling, forwarded to
  // validateSignature. Leaving them out keeps the defaults.
  const signatureOptions: ValidateSignatureOptions = {
    allowedSignatureAlgorithms: options.allowedSignatureAlgorithms,
    allowedHashAlgorithms: options.allowedHashAlgorithms,
    maxSignatureReferences: options.maxSignatureReferences,
  };

  // decryptXml parses with parseFromString, which already reports any
  // multi-rooted document as multiRootedXMLError.
  const {
    assertion: decryptedResponse,
    decrypted: decAssertion,
    encrypted,
  } = decryptXml(rawAssertion, options);
  rawAssertion = decryptedResponse;

  // rawAssertion is our SAML Response. However, we still call it rawAssertion because of legacy naming convention
  const responseObj = xmlToJs(rawAssertion);

  // Stop on a non-Success status. Carrying on would run signature checks and,
  // worse, the caller's replay validator, which may record the assertion as
  // used even though the response is rejected here.
  const statusError = getStatusCodeError(responseObj);
  if (statusError) {
    throw statusError;
  }

  let signedXml = checkSignature(rawAssertion, options, signatureOptions);

  if (decAssertion && !signedXml) {
    // try the fallback verification where signature has been generated on the encrypted SAML by some IdPs (like OpenAthens)
    signedXml = checkSignature(originalAssertion, options, signatureOptions);
  }

  if (!signedXml) {
    throw new Error('Invalid assertion signature.');
  }

  // signedXml is either: Assertion or Response XML
  // in the case of Response XML, we have to handle the Responses with the encrypted SAML Responses
  // so let's use the previous helper function to decrypt response once again (if it is one)
  // if no decryption occured, then decryptedSignedXml is just signedXml
  const { assertion: decryptedSignedXml, encrypted: signedEncrypted } = decryptXml(signedXml, {
    privateKey: options.privateKey,
    reportEncryption: options.reportEncryption,
  });

  const assertionObj = xmlToJs(decryptedSignedXml); // this is our assertion object

  const { assertion, signed } = parseResponseAndVersion(assertionObj);

  // checkAssertion returns the error for an assertion that fails a check.
  // Anything it throws is unexpected and is wrapped instead.
  let failure: Error | undefined;
  try {
    failure = await checkAssertion(assertion, signed, options);
  } catch (e) {
    const error = new WrapError('An error occurred trying to validate the assertion.');
    error.inner = e as Error;
    throw error;
  }
  if (failure) {
    throw failure;
  }

  const profile = parseAttributes(assertion);
  const encryption = options.reportEncryption
    ? reportEncryption({
        signedEncrypted,
        encrypted,
        assertionSigned: !assertionObj?.Response,
        original: originalAssertion,
        options,
        signatureOptions,
      })
    : undefined;
  if (encryption) {
    profile.encryption = encryption;
  }
  return profile;
};

// How the assertion that validated was protected, or undefined when that
// assertion was not encrypted or cannot be told apart from another one.
const reportEncryption = ({
  signedEncrypted,
  encrypted,
  assertionSigned,
  original,
  options,
  signatureOptions,
}: {
  signedEncrypted?: EncryptedResponse;
  encrypted?: EncryptedResponse;
  assertionSigned: boolean;
  original: string;
  options: ValidateOptions;
  signatureOptions: ValidateSignatureOptions;
}): AssertionEncryption | undefined => {
  // The signed content held the ciphertext the assertion was decrypted from.
  if (signedEncrypted) {
    return {
      dataAlgorithm: signedEncrypted.dataAlgorithm,
      keyTransportAlgorithm: signedEncrypted.keyTransportAlgorithm,
      signaturePlacement: 'response',
    };
  }
  // Otherwise the assertion was read in plaintext from the signed content,
  // which is the decrypted one only when no other assertion is present.
  if (!encrypted || encrypted.assertionCount !== 1) {
    return undefined;
  }
  // A signed assertion leaves the Response's own signature unchecked, so that
  // one is verified here; a Response verified only once decrypted never
  // covered the ciphertext.
  const covered =
    assertionSigned &&
    encrypted.responseSigned &&
    rootSignatureCoversCiphertext(original, encrypted.responseId, options, signatureOptions);
  return {
    dataAlgorithm: encrypted.dataAlgorithm,
    keyTransportAlgorithm: encrypted.keyTransportAlgorithm,
    signaturePlacement: covered ? 'response' : 'assertion_only',
  };
};

const rootSignatureCoversCiphertext = (
  original: string,
  responseId: string | undefined,
  options: ValidateOptions,
  signatureOptions: ValidateSignatureOptions
): boolean => {
  let signed: string | null;
  try {
    signed = verifyRootSignature(original, options.publicKey, options.thumbprint, signatureOptions);
  } catch {
    return false;
  }
  const root = signed ? parseFromString(signed)?.documentElement : undefined;
  if (!root || !responseId || root.localName !== 'Response' || root.getAttribute('ID') !== responseId) {
    return false;
  }
  const covering = select(
    "/*[local-name(.)='Response']/*[local-name(.)='EncryptedAssertion']",
    // @ts-expect-error missing Node properties are not needed
    root.ownerDocument
  ) as Node[];
  return covering.length > 0;
};

// Verify the signature; a thrown verification error becomes "Invalid
// assertion." with the cause in `inner`. Returns the signed XML, or null when
// the signature does not verify.
const checkSignature = (
  xml: string,
  options: ValidateOptions,
  signatureOptions: ValidateSignatureOptions
): string | null => {
  try {
    return verifySignature(xml, options.publicKey, options.thumbprint, signatureOptions);
  } catch (e) {
    const error = new WrapError('Invalid assertion.');
    error.inner = e as Error;
    throw error;
  }
};

// The checks on a signed assertion, in order. Returns the error to reject
// with, or undefined when every check passes.
// Values read from the signed content only (see parseResponseAndVersion).
type SignedValues = { inResponseTo?: string; signedDestination?: string };

const checkAssertion = async (
  assertion: XmlNode,
  signed: SignedValues,
  options: ValidateOptions
): Promise<Error | undefined> => {
  if (!options.bypassExpiration && !saml20.validateExpiration(assertion)) {
    return new Error('Assertion is expired.');
  }

  if (!saml20.validateAudience(assertion, options.audience)) {
    return new Error('Invalid audience.');
  }

  // Fail closed: when the caller supplies an expected InResponseTo (an
  // SP-initiated flow), the assertion must carry a matching, signed
  // InResponseTo. A missing value is a mismatch, not a reason to skip the
  // check, otherwise a captured assertion can be replayed into a different
  // login by stripping InResponseTo from the unsigned <Response> wrapper.
  if (options.inResponseTo && signed.inResponseTo !== options.inResponseTo) {
    return new Error('Invalid InResponseTo.');
  }

  // Fail closed: when the caller supplies the ACS URL(s) the response may
  // have been posted to, the signed content must name one of them (see
  // validateRecipient for the exact rule). Without this, an assertion issued for one SP endpoint
  // can be posted to another that shares the IdP signing key and the
  // audience. The unsigned <Response> wrapper is never consulted, so
  // editing its Destination cannot satisfy the check.
  if (
    options.recipient &&
    !saml20.validateRecipient(assertion, signed.signedDestination, options.recipient, {
      bypassExpiration: options.bypassExpiration,
    })
  ) {
    return new Error('Invalid Recipient.');
  }

  // Optional one-time replay protection. The library is stateless, so the
  // caller supplies the store. The callback receives the signed assertion
  // identifiers and must return true when the assertion has already been
  // seen (a replay), keying entries by assertion ID until NotOnOrAfter.
  if (typeof options.assertionReplayValidator === 'function') {
    let alreadyUsed: boolean;
    try {
      alreadyUsed = await options.assertionReplayValidator({
        assertionId: saml20.getAssertionId(assertion),
        sessionIndex: getAttribute<string | undefined>(assertion, 'AuthnStatement.@.SessionIndex'),
        // Effective expiry (Conditions or the latest bearer confirmation), so
        // the caller can size the replay-cache TTL to cover the whole window
        // an assertion can still validate.
        notOnOrAfter: saml20.getNotOnOrAfter(assertion),
        inResponseTo: signed.inResponseTo,
      });
    } catch (e) {
      const error = new WrapError('An error occurred during assertion replay validation.');
      error.inner = e as Error;
      return error;
    }
    if (alreadyUsed) {
      return new Error('Assertion has already been used (replay detected).');
    }
  }

  return undefined;
};

const xmlToJs = (rawAssertion: string) => {
  try {
    return xmlToObject(sanitizeXML(rawAssertion), { attrkey: '@', collapse: true });
  } catch (err) {
    const error = new WrapError('An error occurred trying to parse XML assertion.');
    error.inner = err as Error;
    throw error;
  }
};

// Returns an error for a top-level StatusCode other than Success, or undefined
// when the status is Success or absent.
const getStatusCodeError = (responseObj: XmlNode | null): Error | undefined => {
  const statusValue = getAttribute<string | undefined>(responseObj, 'Response.Status.StatusCode.@.Value');
  const status = statusValue ? statusValue.split(':').pop() : undefined;

  if (status && status !== 'Success') {
    return new Error(`Invalid Status Code (${status}).`);
  }
  return undefined;
};

/*
  assertionObj: the signed content: a whole SAML Response, a lone Assertion,
  or a whole WS-Trust RequestSecurityTokenResponse (ADFS over WS-Federation).
  Only signed content is read here, never an unsigned wrapper around a signed
  Assertion.
 */
function parseResponseAndVersion(assertionObj: XmlNode | null) {
  const root = assertionObj || {};
  let assertion: XmlValue | undefined =
    getAttribute<XmlValue | undefined>(root, 'Assertion') ||
    getAttribute<XmlValue | undefined>(root, 'Response.Assertion') ||
    getAttribute<XmlValue | undefined>(root, 'RequestSecurityTokenResponse.RequestedSecurityToken.Assertion');
  // if we have an array of assertions then pick first element
  if (Array.isArray(assertion) && assertion[0]) {
    assertion = assertion[0];
  }

  if (!assertion) {
    throw new Error('Invalid assertion.');
  }

  // Only an element can carry Version; text or a list never does.
  if (typeof assertion !== 'object' || Array.isArray(assertion) || !getVersion(assertion)) {
    throw new Error('SAML Assertion version not supported.');
  }

  // Derive InResponseTo only from signed content so it cannot be forged by
  // tampering with the unsigned <Response> wrapper. When the whole Response is
  // signed, `assertionObj` is the Response subtree and Response/@InResponseTo is
  // trustworthy. In the common assertion-only-signed case, fall back to the
  // bearer SubjectConfirmationData/@InResponseTo, which is inside the signed
  // assertion. The unsigned wrapper around a signed Assertion is never read.
  const signedResponseInResponseTo = root.Response ? saml20.getInResponseTo(root) : undefined;
  const inResponseTo: string | undefined =
    signedResponseInResponseTo || saml20.getSubjectConfirmationInResponseTo(assertion);

  // Same rule for where the message was addressed: Response/@Destination is
  // only used when the whole Response is signed. The bearer Recipients are read
  // from the signed assertion by validateRecipient.
  const signedDestination: string | undefined = root.Response ? saml20.getDestination(root) : undefined;

  return { assertion, signed: { inResponseTo, signedDestination } };
}

function parseAttributes(assertion: XmlNode): SAMLProfile {
  try {
    return saml20.parse(assertion);
  } catch (e) {
    const error = new WrapError('An error occurred trying to parse assertion.');
    error.inner = e as Error;
    throw error;
  }
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
const createSAMLResponse = async ({
  audience,
  issuer,
  acsUrl,
  claims,
  requestId,
  privateKey,
  publicKey,
  flattenArray = false,
  ttlInMinutes,
  sessionIndex,
}: {
  audience: string;
  issuer: string;
  acsUrl: string;
  // oxlint-disable-next-line typescript/no-explicit-any -- caller-defined claim values
  claims: Record<string, any>;
  requestId: string;
  privateKey: string;
  publicKey: string;
  flattenArray?: boolean;
  ttlInMinutes?: number;
  // The AuthnStatement SessionIndex, which an SP sends back in its LogoutRequest
  // to name the session to end. Defaults to requestId.
  sessionIndex?: string;
}): Promise<string> => {
  const clockSkewToleranceMinutes = 5;
  const authDate = new Date();
  const authTimestamp = authDate.toISOString();

  authDate.setMinutes(authDate.getMinutes() - clockSkewToleranceMinutes);
  const notBefore = authDate.toISOString();

  authDate.setMinutes(authDate.getMinutes() + clockSkewToleranceMinutes + (ttlInMinutes || 10));
  const notAfter = authDate.toISOString();

  const nodes = {
    'samlp:Response': {
      '@Destination': acsUrl,
      '@ID': generateId(),
      '@InResponseTo': requestId,
      '@IssueInstant': authTimestamp,
      '@Version': '2.0',
      '@xmlns:samlp': PROTOCOL_NS,
      'saml:Issuer': {
        '@Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
        '@xmlns:saml': ASSERTION_NS,
        '#text': issuer,
      },
      'samlp:Status': {
        '@xmlns:samlp': PROTOCOL_NS,
        'samlp:StatusCode': {
          '@Value': 'urn:oasis:names:tc:SAML:2.0:status:Success',
        },
      },
      'saml:Assertion': {
        '@ID': generateId(),
        '@IssueInstant': authTimestamp,
        '@Version': '2.0',
        '@xmlns:saml': ASSERTION_NS,
        '@xmlns:xs': XML_SCHEMA_NS,
        'saml:Issuer': {
          '@Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
          '@xmlns:saml': ASSERTION_NS,
          '#text': issuer,
        },
        'saml:Subject': {
          '@xmlns:saml': ASSERTION_NS,
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
          '@xmlns:saml': ASSERTION_NS,
          'saml:AudienceRestriction': {
            'saml:Audience': {
              '#text': audience,
            },
          },
        },
        'saml:AuthnStatement': {
          '@AuthnInstant': authTimestamp,
          '@SessionIndex': sessionIndex || requestId,
          '@xmlns:saml': ASSERTION_NS,
          'saml:AuthnContext': {
            'saml:AuthnContextClassRef': {
              '#text': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            },
          },
        },
        'saml:AttributeStatement': {
          '@xmlns:saml': ASSERTION_NS,
          'saml:Attribute': Object.keys(claims.raw || []).map((attributeName) => {
            const attributeValue = claims.raw[attributeName];
            const attributeValueArray = Array.isArray(attributeValue)
              ? flattenArray
                ? flattenedArray(attributeValue)
                : attributeValue
              : [attributeValue];

            return {
              '@Name': attributeName,
              '@NameFormat': nameFormat(attributeName),
              'saml:AttributeValue': attributeValueArray.map((value) => {
                return {
                  '@xmlns:xs': XML_SCHEMA_NS,
                  '@xmlns:xsi': XML_SCHEMA_INSTANCE_NS,
                  '@xsi:type': 'xs:string',
                  '#text': value,
                };
              }),
            };
          }),
        },
      },
    },
  };

  const xml = buildXml(nodes, { encoding: 'UTF-8' });

  const signedAssertionXml = sign(xml, privateKey, publicKey, '//*[local-name(.)="Assertion"]');

  const signedXml = sign(
    signedAssertionXml,
    privateKey,
    publicKey,
    `/*[local-name(.)="Response" and namespace-uri(.)="${PROTOCOL_NS}"]`
  );

  return signedXml;
};

export { createSAMLResponse, validate, parseIssuer, WrapError };
