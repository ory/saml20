import xmlbuilder from 'xmlbuilder';
import { generateId, getAttribute } from './utils';
import { xmlToObject } from './xml';
import type { XmlValue } from './xml';
import { ASSERTION_NS, PROTOCOL_NS } from './constants';

type ParsedLogoutResponse = {
  id: string;
  issuer: string;
  status: string;
  // Both are optional on the wire; undefined when the response omits them.
  destination?: string;
  inResponseTo?: string;
};

type LogoutRequestParams = {
  nameId: string;
  /**
   * The Format of the NameID, as the IdP asserted it. Defaults to
   * `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. An IdP that
   * matches the NameID it issued exactly may need the asserted format.
   */
  nameIdFormat?: string;
  /** The NameQualifier of the NameID, as the IdP asserted it. Left out when unset. */
  nameQualifier?: string;
  /** The SPNameQualifier of the NameID, as the IdP asserted it. Left out when unset. */
  spNameQualifier?: string;
  providerName: string;
  sloUrl: string;
  /**
   * The SessionIndex of the session to end, as the IdP asserted it in the
   * AuthnStatement of the sign-in. Without one, the LogoutRequest names only the
   * user, and the IdP ends every session it holds for them. Several end each of
   * those sessions.
   */
  sessionIndex?: string | string[];
};

// Text content of the first element in a child list. xmlToObject yields a
// plain string for an element without attributes and `{ _: text, $: attrs }`
// for one with attributes (a namespace declaration counts as an attribute).
const textOf = (elements: XmlValue | undefined): string | undefined => {
  const first = getAttribute<XmlValue | undefined>(elements, '0');
  return typeof first === 'string' ? first : getAttribute<string | undefined>(first, '_');
};

const parseLogoutResponse = async (rawResponse: string): Promise<ParsedLogoutResponse> => {
  const parsedData = xmlToObject(rawResponse, { attrkey: '$' });
  const LogoutResponse = getAttribute<XmlValue | undefined>(parsedData, 'LogoutResponse');

  if (!LogoutResponse) {
    throw new Error('Invalid SAML LogoutResponse: missing LogoutResponse element.');
  }

  const status = getAttribute<string | undefined>(LogoutResponse, 'Status[0].StatusCode[0].$.Value');
  if (!status) {
    throw new Error('Invalid SAML LogoutResponse: missing StatusCode.');
  }

  return {
    issuer: textOf(getAttribute<XmlValue | undefined>(LogoutResponse, 'Issuer')) as string,
    id: getAttribute<string>(LogoutResponse, '$.ID'),
    status,
    destination: getAttribute<string | undefined>(LogoutResponse, '$.Destination'),
    inResponseTo: getAttribute<string | undefined>(LogoutResponse, '$.InResponseTo'),
  };
};

const createLogoutRequest = ({
  nameId,
  nameIdFormat,
  nameQualifier,
  spNameQualifier,
  providerName,
  sloUrl,
  sessionIndex,
}: LogoutRequestParams): { id: string; xml: string } => {
  const id = generateId();
  const sessionIndexes = (Array.isArray(sessionIndex) ? sessionIndex : [sessionIndex]).filter(
    (value): value is string => typeof value === 'string' && value.length > 0
  );

  const xml = {
    'samlp:LogoutRequest': {
      '@xmlns:samlp': PROTOCOL_NS,
      '@xmlns:saml': ASSERTION_NS,
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': new Date().toISOString(),
      '@Destination': sloUrl,
      'saml:Issuer': {
        '#text': providerName,
      },
      'saml:NameID': {
        ...(nameQualifier && { '@NameQualifier': nameQualifier }),
        ...(spNameQualifier && { '@SPNameQualifier': spNameQualifier }),
        '@Format': nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        '#text': nameId,
      },
      // After the NameID, as the schema orders a LogoutRequest's children.
      ...(sessionIndexes.length > 0 && {
        'samlp:SessionIndex': sessionIndexes.map((value) => ({ '#text': value })),
      }),
    },
  };

  return {
    id,
    xml: xmlbuilder.create(xml).end({}),
  };
};

type ParsedLogoutRequest = {
  id: string;
  issuer: string;
  nameId: string;
  sessionIndex?: string;
  destination?: string;
  /**
   * The request's IssueInstant, as the sender wrote it. A relying party needs it
   * to reject a request that is too old to act on, which a signature alone
   * cannot tell it.
   */
  issueInstant?: string;
  publicKey?: string;
  idToken?: string;
};

type LogoutResponseParams = {
  requestId: string;
  issuer: string;
  destination: string;
  status?: string;
};

const parseLogoutRequest = async (rawRequest: string): Promise<ParsedLogoutRequest> => {
  const parsedData = xmlToObject(rawRequest, { attrkey: '$' });
  // xmlToObject yields null for an empty document and '' for an element with no
  // attributes and no children; neither is a usable LogoutRequest.
  const LogoutRequest = getAttribute<XmlValue | undefined>(parsedData, 'LogoutRequest');

  if (!LogoutRequest) {
    throw new Error('Invalid SAML LogoutRequest: missing LogoutRequest element.');
  }

  const id = getAttribute<string>(LogoutRequest, '$.ID');
  const destination = getAttribute<string | undefined>(LogoutRequest, '$.Destination');
  const issueInstant = getAttribute<string | undefined>(LogoutRequest, '$.IssueInstant');

  const issuer = textOf(getAttribute<XmlValue | undefined>(LogoutRequest, 'Issuer')) ?? '';
  const nameId = textOf(getAttribute<XmlValue | undefined>(LogoutRequest, 'NameID')) ?? '';
  const sessionIndex = textOf(getAttribute<XmlValue | undefined>(LogoutRequest, 'SessionIndex'));

  // Extract public key from Signature > KeyInfo > X509Data > X509Certificate if present
  let publicKey: string | undefined;
  const x509Cert = getAttribute<XmlValue | undefined>(
    LogoutRequest,
    'Signature[0].KeyInfo[0].X509Data[0].X509Certificate[0]'
  );
  if (x509Cert) {
    publicKey = typeof x509Cert === 'string' ? x509Cert : getAttribute<string | undefined>(x509Cert, '_');
  }

  // Extract id_token from Extensions > IdToken if present
  // The SP can embed the OIDC id_token inside the LogoutRequest so it is
  // covered by the XML signature.
  let idToken: string | undefined;
  const idTokenElement = getAttribute<XmlValue | undefined>(LogoutRequest, 'Extensions[0].Attribute[0]');
  if (getAttribute(idTokenElement, '$.Name') === 'id_token') {
    const attrVal = getAttribute<XmlValue | undefined>(idTokenElement, 'AttributeValue[0]');
    idToken = typeof attrVal === 'string' ? attrVal : getAttribute<string | undefined>(attrVal, '_');
  }

  return {
    id,
    issuer,
    nameId,
    sessionIndex,
    destination,
    issueInstant,
    publicKey,
    idToken,
  };
};

const createLogoutResponse = ({
  requestId,
  issuer,
  destination,
  status = 'urn:oasis:names:tc:SAML:2.0:status:Success',
}: LogoutResponseParams): { id: string; xml: string } => {
  const id = generateId();

  const xml = {
    'samlp:LogoutResponse': {
      '@xmlns:samlp': PROTOCOL_NS,
      '@xmlns:saml': ASSERTION_NS,
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': new Date().toISOString(),
      '@Destination': destination,
      '@InResponseTo': requestId,
      'saml:Issuer': {
        '#text': issuer,
      },
      'samlp:Status': {
        'samlp:StatusCode': {
          '@Value': status,
        },
      },
    },
  };

  return {
    id,
    xml: xmlbuilder.create(xml).end({}),
  };
};

export { parseLogoutResponse, createLogoutRequest, parseLogoutRequest, createLogoutResponse };

export type { ParsedLogoutResponse, LogoutRequestParams, ParsedLogoutRequest, LogoutResponseParams };
