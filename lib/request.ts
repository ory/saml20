import { promisify } from 'util';
import xml2js from 'xml2js';
import { inflateRaw } from 'zlib';
import xmlbuilder from 'xmlbuilder';
import { SAMLReq } from './typings';
import crypto from 'crypto';
import { containsDoctype, doctypeNotAllowedError } from './utils';
import { sign } from './sign';

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

const idPrefix = '_';
const authnXPath =
  '/*[local-name(.)="AuthnRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';

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
  const id = idPrefix + crypto.randomBytes(10).toString('hex');
  const date = new Date().toISOString();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const samlReq: Record<string, any> = {
    'samlp:AuthnRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': date,
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Destination': ssoUrl,
      'saml:Issuer': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
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
    '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
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

// Parse XML
const parseXML = (xml: string): Promise<Record<string, any>> => {
  return new Promise((resolve, reject) => {
    if (containsDoctype(xml)) {
      reject(doctypeNotAllowedError);
      return;
    }
    xml2js.parseString(
      xml,
      {
        tagNameProcessors: [xml2js.processors.stripPrefix],
        strict: true,
      },
      (err: Error | null, result: any) => {
        if (err) {
          reject(err);
        }

        resolve(result);
      }
    );
  });
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
  const result = await parseXML(rawRequest);

  const attributes = result['AuthnRequest']['$'];
  const issuer = result['AuthnRequest']['Issuer'];

  const publicKey = result['AuthnRequest']['Signature']
    ? result['AuthnRequest']['Signature'][0]['KeyInfo'][0]['X509Data'][0]['X509Certificate'][0]
    : null;

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
