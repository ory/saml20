import { promisify } from 'util';
import { inflateRaw } from 'zlib';
import xmlbuilder from 'xmlbuilder';
import { SAMLReq } from './typings';
import { generateId } from './utils';
import { xmlToObject } from './xml';
import { sign } from './sign';
import { ASSERTION_NS, PROTOCOL_NS } from './constants';

const inflateRawAsync = promisify(inflateRaw);

// Ceilings for decoding a SAMLRequest, which on the HTTP-Redirect binding
// arrives as an unauthenticated query parameter. A legitimate deflated, base64
// request is a few KB; both limits sit far above real traffic yet bound the
// memory a caller can be made to allocate for one. DEFLATE reaches roughly
// 1000:1 on repetitive input, so without the output bound a few hundred
// compressed bytes expand to hundreds of megabytes.
const MAX_ENCODED_REQUEST_LENGTH = 1024 * 1024;
const MAX_INFLATED_REQUEST_BYTES = 10 * 1024 * 1024;

const samlRequestTooLargeError = new Error('saml request is too large.');
const samlRequestDecodeError = new Error('saml request could not be decoded.');

type DecodeBase64Options = {
  /** Maximum length of the encoded input, in characters. */
  maxEncodedLength?: number;
  /** Maximum size of the inflated output, in bytes. */
  maxOutputLength?: number;
};

const authnXPath = `/*[local-name(.)="AuthnRequest" and namespace-uri(.)="${PROTOCOL_NS}"]`;

const request = ({
  ssoUrl,
  entityID,
  callbackUrl,
  isPassive = false,
  forceAuthn = false,
  identifierFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  providerName = 'BoxyHQ',
  signingKey,
  publicKey,
}: SAMLReq): { id: string; request: string } => {
  const id = generateId();
  const date = new Date().toISOString();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const samlReq: Record<string, any> = {
    'samlp:AuthnRequest': {
      '@xmlns:samlp': PROTOCOL_NS,
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': date,
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Destination': ssoUrl,
      'saml:Issuer': {
        '@xmlns:saml': ASSERTION_NS,
        '#text': entityID,
      },
    },
  };

  if (isPassive) samlReq['samlp:AuthnRequest']['@IsPassive'] = true;

  if (forceAuthn) {
    samlReq['samlp:AuthnRequest']['@ForceAuthn'] = true;
  }

  samlReq['samlp:AuthnRequest']['@AssertionConsumerServiceURL'] = callbackUrl;

  samlReq['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
    '@xmlns:samlp': PROTOCOL_NS,
    '@Format': identifierFormat,
    '@AllowCreate': 'true',
  };

  if (providerName != null) {
    samlReq['samlp:AuthnRequest']['@ProviderName'] = providerName;
  }

  let xml = xmlbuilder.create(samlReq).end({});
  if (signingKey) {
    xml = sign(xml, signingKey, publicKey, authnXPath);
  }

  return {
    id,
    request: xml,
  };
};

// Decode the base64 string
const decodeBase64 = async (string: string, isDeflated: boolean, options: DecodeBase64Options = {}) => {
  const maxEncodedLength = options.maxEncodedLength ?? MAX_ENCODED_REQUEST_LENGTH;
  const maxOutputLength = options.maxOutputLength ?? MAX_INFLATED_REQUEST_BYTES;

  if (string.length > maxEncodedLength) {
    throw samlRequestTooLargeError;
  }

  const buffer = Buffer.from(string, 'base64');

  if (!isDeflated) {
    return buffer.toString();
  }

  try {
    return (await inflateRawAsync(buffer, { maxOutputLength })).toString();
  } catch {
    // zlib throws ERR_BUFFER_TOO_LARGE once the output passes maxOutputLength,
    // and other errors on malformed input. Neither is relayed verbatim, so the
    // raw zlib text cannot be used to probe how the input was handled.
    throw samlRequestDecodeError;
  }
};

// Parse SAMLRequest attributes
const parseSAMLRequest = async (rawRequest: string, isPost = true) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const result: any = xmlToObject(rawRequest, { attrkey: '$' });

  // xmlToObject yields '' for an AuthnRequest with no attributes and no children.
  // The element is there, so report what is missing from it instead.
  const authnRequest = result?.['AuthnRequest'];
  if (authnRequest === undefined || authnRequest === null) {
    throw new Error('Invalid SAML Request: missing AuthnRequest element.');
  }

  const attributes = authnRequest['$'] || {};
  const issuer = authnRequest['Issuer'];

  // The embedded certificate is only returned here; verifying the signature
  // against it (or against a trusted key) is the caller's job. A Signature
  // without a certificate yields null, the same as no Signature at all.
  const x509Certificate =
    authnRequest['Signature']?.[0]?.['KeyInfo']?.[0]?.['X509Data']?.[0]?.['X509Certificate']?.[0];
  const publicKey: string | null =
    (typeof x509Certificate === 'string' ? x509Certificate : x509Certificate?._) || null;

  if (!issuer) {
    throw new Error("Missing 'Issuer' in SAML Request.");
  }

  if (!publicKey && isPost) {
    throw new Error('Missing signature');
  }

  return {
    id: attributes.ID,
    acsUrl: attributes.AssertionConsumerServiceURL,
    providerName: attributes.ProviderName,
    audience: issuer[0]['_'] ?? issuer[0], // also known as entityID
    publicKey,
  };
};

export {
  request,
  parseSAMLRequest,
  decodeBase64,
  samlRequestTooLargeError,
  samlRequestDecodeError,
  MAX_ENCODED_REQUEST_LENGTH,
  MAX_INFLATED_REQUEST_BYTES,
};
export type { DecodeBase64Options };
