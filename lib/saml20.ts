import { getAttribute } from './utils';

const permanentNameIdentifier = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
const nameIdentifierClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';
const emailAddressClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';
const givenNameClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname';
const surnameClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname';
const nameidFormatEmailAddress = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

function getClaims(attributes) {
  const claims = {};

  attributes.forEach(function attributesForEach(attribute) {
    const attributeName = attribute['@'].Name;
    const friendlyName = attribute['@'].FriendlyName;

    const extProp = getExtendedProp(attribute, 'AttributeValue', 'NameID');

    claims[attributeName] = extProp.result;

    if (friendlyName === 'email') {
      claims[emailAddressClaimType] = extProp.result;
    } else if (friendlyName === 'givenName') {
      claims[givenNameClaimType] = extProp.result;
    } else if (friendlyName === 'sn') {
      claims[surnameClaimType] = extProp.result;
    }

    if (extProp.format === permanentNameIdentifier) {
      claims[nameIdentifierClaimType] = extProp.result;
    }
  });

  return claims;
}

function trimWords(phrase) {
  return phrase
    .split(' ')
    .map(function wordMapping(w) {
      return w.trim();
    })
    .filter(function wordFiltering(w) {
      return !!w;
    })
    .join(' ');
}

function getExtendedProp(obj, prop?: string, extraProp?: string) {
  let result = prop ? getAttribute(obj, prop) : obj;
  const format = result && result['@'] && result['@'].Format ? result['@'].Format : null;

  if (result && result._) {
    result = result._;
  }

  if (typeof result === 'string') {
    return {
      result: trimWords(result),
      format,
    };
  } else if (Array.isArray(result)) {
    // Build a new array rather than overwriting the parsed object in place.
    return { result: result.map((item) => getProp(item)), format };
  } else if (extraProp && result && result[extraProp!]) {
    return getExtendedProp(result[extraProp!]);
  }

  return {};
}

function getProp(obj, prop?: string, extraProp?: string) {
  return getExtendedProp(obj, prop, extraProp).result;
}

const parse = (assertion) => {
  let claims = {};
  let attributes = getAttribute(assertion, 'AttributeStatement.Attribute');

  if (attributes) {
    attributes = attributes instanceof Array ? attributes : [attributes];
    claims = getClaims(attributes);
  }

  const subjectNameObj = getExtendedProp(assertion, 'Subject.NameID');
  const subjectName = subjectNameObj.result;

  if (subjectName && !claims[nameIdentifierClaimType]) {
    claims[nameIdentifierClaimType] = subjectName;
  }

  if (subjectName && subjectNameObj.format === nameidFormatEmailAddress && !claims[emailAddressClaimType]) {
    claims[emailAddressClaimType] = subjectName;
  }

  const audiences = getAudienceRestrictions(assertion)
    .flat()
    .filter((audience): audience is string => typeof audience === 'string');

  return {
    audience: audiences[0],
    audiences,
    claims: claims,
    issuer: getProp(assertion, 'Issuer'),
    sessionIndex: getProp(assertion, 'AuthnStatement.@.SessionIndex'),
    assertionId: getAssertionId(assertion),
    notOnOrAfter: getNotOnOrAfter(assertion),
  };
};

const audienceCheck = (audience, expectedAudience, strictValidation) => {
  if (typeof audience !== 'string' || typeof expectedAudience !== 'string') {
    return false;
  }

  if (strictValidation) {
    return audience === expectedAudience;
  }

  return audience.startsWith(expectedAudience);
};

const toArray = <T>(value: T | T[] | undefined | null): T[] => {
  if (value === undefined || value === null) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

// The <Audience> values of each <AudienceRestriction>, in document order.
const getAudienceRestrictions = (assertion): unknown[][] =>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  toArray<any>(getAttribute<any>(assertion, 'Conditions.AudienceRestriction')).map((restriction) =>
    toArray(getAttribute(restriction, 'Audience')).map((audience) => getProp(audience))
  );

// SAML core 2.5.1.4: an assertion may carry several <AudienceRestriction>
// elements, and each must be satisfied; within one <AudienceRestriction> the
// <Audience> values are alternatives, so any one of them may name the relying
// party. `realm` is the relying party's own identifier, or a list of them.
const validateAudience = (assertion, realm, strictValidation = false) => {
  try {
    const expected = toArray(realm);
    const restrictions = getAudienceRestrictions(assertion);
    if (restrictions.length === 0 || expected.length === 0) {
      return false;
    }

    return restrictions.every((audiences) => {
      return audiences.some((audience) =>
        expected.some((expectedAudience) => audienceCheck(audience, expectedAudience, strictValidation))
      );
    });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (err) {
    return false;
  }
};

const clockSkewMs = 10 * 60 * 1000; // 10 minutes clock skew.

const BEARER_METHOD = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

// Collect the SubjectConfirmationData elements across the SubjectConfirmation
// entries: all of them, or with `bearerOnly` only those of bearer
// confirmations. Bearer assertions carry their expiration here rather than
// (or in addition to) Conditions.
const getSubjectConfirmationData = (
  assertion,
  { bearerOnly = false }: { bearerOnly?: boolean } = {}
): Record<string, unknown>[] => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let confirmations = getAttribute<any>(assertion, 'Subject.SubjectConfirmation');
  if (!confirmations) {
    return [];
  }
  confirmations = Array.isArray(confirmations) ? confirmations : [confirmations];
  const data: Record<string, unknown>[] = [];
  for (const confirmation of confirmations) {
    if (bearerOnly && confirmation?.['@']?.Method !== BEARER_METHOD) {
      continue;
    }
    let scd = getAttribute<Record<string, unknown> | Record<string, unknown>[]>(
      confirmation,
      'SubjectConfirmationData'
    );
    if (!scd) {
      continue;
    }
    scd = Array.isArray(scd) ? scd : [scd];
    data.push(...scd);
  }
  return data;
};

// Check a [NotBefore, NotOnOrAfter] window against now, applying clock skew.
// Returns 'unbounded' when no NotOnOrAfter is present (the window has no upper
// limit), 'valid' when now is inside the window, and 'invalid' when a bound is
// present but unparseable or now falls outside it.
type WindowResult = 'valid' | 'invalid' | 'unbounded';
const checkWindow = (notBefore?: string, notOnOrAfter?: string): WindowResult => {
  const now = Date.now();

  if (notBefore) {
    const ms = new Date(notBefore).getTime();
    if (Number.isNaN(ms) || now < ms - clockSkewMs) {
      return 'invalid';
    }
  }

  if (!notOnOrAfter) {
    return 'unbounded';
  }
  const ms = new Date(notOnOrAfter).getTime();
  if (Number.isNaN(ms) || now > ms + clockSkewMs) {
    return 'invalid';
  }
  return 'valid';
};

const validateExpiration = (assertion) => {
  // The <Conditions> window is an absolute constraint on the assertion (SAML
  // core 2.5.1): when present it must be satisfied. A present-but-unparseable
  // bound is treated as invalid.
  const conditionsNotBefore = getAttribute<string | undefined>(assertion, 'Conditions.@.NotBefore');
  const conditionsNotOnOrAfter = getAttribute<string | undefined>(assertion, 'Conditions.@.NotOnOrAfter');
  const conditionsResult = checkWindow(conditionsNotBefore, conditionsNotOnOrAfter);
  if (conditionsResult === 'invalid') {
    return false;
  }

  // The Web Browser SSO profile (4.1.4.3) requires verifying the NotOnOrAfter on
  // the bearer SubjectConfirmationData, independently of Conditions. Multiple
  // SubjectConfirmation elements are alternatives (core 2.4.1.1), so when any
  // bearer confirmation carries a NotOnOrAfter, at least one such confirmation
  // must still be within its window — even if Conditions is otherwise valid.
  const bearerBounds = getSubjectConfirmationData(assertion).filter(
    (scd) => (scd['@'] as Record<string, string> | undefined)?.NotOnOrAfter
  );
  if (bearerBounds.length > 0) {
    return bearerBounds.some((scd) => {
      const attrs = scd['@'] as Record<string, string>;
      return checkWindow(attrs.NotBefore, attrs.NotOnOrAfter) === 'valid';
    });
  }

  // No bearer expiration is present: rely on a satisfied Conditions upper bound.
  // An assertion with no enforceable upper bound anywhere is rejected rather
  // than treated as "never expires" (the original NaN defect).
  return conditionsResult === 'valid';
};

// InResponseTo read from the outer <Response> wrapper. Only trust this when the
// whole Response is signed; the wrapper is unsigned in the common
// assertion-only-signed case.
const getInResponseTo = (xml) => {
  return getProp(xml, 'Response.@.InResponseTo');
};

// InResponseTo carried inside the bearer SubjectConfirmationData. This element
// lives inside the <Assertion> and is therefore covered by the assertion
// signature even when the outer <Response> wrapper is not signed.
const getSubjectConfirmationInResponseTo = (assertion): string | undefined => {
  for (const scd of getSubjectConfirmationData(assertion)) {
    const inResponseTo = (scd['@'] as Record<string, string> | undefined)?.InResponseTo;
    if (inResponseTo) {
      return inResponseTo;
    }
  }
  return undefined;
};

// Destination read from the outer <Response> wrapper. Like getInResponseTo,
// only trust this when the whole Response is signed.
const getDestination = (xml): string | undefined => {
  return getProp(xml, 'Response.@.Destination');
};

// Attributes of the bearer SubjectConfirmationData elements only. These live
// inside the <Assertion> and are covered by the assertion signature even when
// the outer <Response> wrapper is not signed.
const getBearerSubjectConfirmationData = (assertion): Record<string, string>[] =>
  getSubjectConfirmationData(assertion, { bearerOnly: true }).map(
    (item) => (item['@'] as Record<string, string> | undefined) || {}
  );

// Whether the signed content addresses the assertion to `recipient`.
//
// - A signed Response/@Destination, when present, must equal it.
// - When any bearer SubjectConfirmationData carries a Recipient, ONE bearer
//   confirmation must satisfy the Web Browser SSO profile checks together
//   (profiles 4.1.4.2 and 4.1.4.3): its Recipient equals `recipient` AND its
//   own [NotBefore, NotOnOrAfter] window is currently valid. Confirmations are
//   alternatives, so a matching Recipient on a lapsed confirmation cannot be
//   combined with the valid window of a confirmation for another endpoint.
// - A Recipient attribute counts as present even when it is empty: an empty
//   Recipient never matches, so it cannot fall back to the Destination.
// - When no bearer confirmation carries a Recipient, only a signed
//   Destination can name the endpoint, so it must be present.
// - `bypassExpiration` skips the window part only, matching the option of the
//   same name on validate(); the Recipient still has to match.
const validateRecipient = (
  assertion,
  signedDestination: string | undefined,
  recipient: string,
  { bypassExpiration = false }: { bypassExpiration?: boolean } = {}
): boolean => {
  if (signedDestination !== undefined && signedDestination !== recipient) {
    return false;
  }

  const withRecipient = getBearerSubjectConfirmationData(assertion).filter(
    (attrs) => attrs.Recipient !== undefined
  );
  if (withRecipient.length === 0) {
    return signedDestination !== undefined;
  }

  return withRecipient.some(
    (attrs) =>
      attrs.Recipient === recipient &&
      (bypassExpiration || checkWindow(attrs.NotBefore, attrs.NotOnOrAfter) === 'valid')
  );
};

const getAssertionId = (assertion): string | undefined => {
  return getAttribute<string | undefined>(assertion, '@.ID');
};

// The effective NotOnOrAfter after which the assertion can no longer validate,
// mirroring validateExpiration. Both gates must hold, so the assertion stops
// validating at the EARLIEST of the enforced upper bounds: the absolute
// Conditions/@NotOnOrAfter and the bearer confirmation. Because bearer
// confirmations are alternatives, the bearer side is governed by the LATEST
// SubjectConfirmationData/@NotOnOrAfter. Callers key replay-cache TTLs off this
// value, so it must reflect the real window in which the assertion can validate.
const getNotOnOrAfter = (assertion): string | undefined => {
  const upperBounds: string[] = [];

  const conditionsNotOnOrAfter = getAttribute<string | undefined>(assertion, 'Conditions.@.NotOnOrAfter');
  if (conditionsNotOnOrAfter) {
    upperBounds.push(conditionsNotOnOrAfter);
  }

  let latestBearer: string | undefined;
  let latestBearerMs = -Infinity;
  for (const scd of getSubjectConfirmationData(assertion)) {
    const value = (scd['@'] as Record<string, string> | undefined)?.NotOnOrAfter;
    if (!value) {
      continue;
    }
    const ms = new Date(value).getTime();
    if (!Number.isNaN(ms) && ms > latestBearerMs) {
      latestBearerMs = ms;
      latestBearer = value;
    }
  }
  if (latestBearer) {
    upperBounds.push(latestBearer);
  }

  let earliest: string | undefined;
  let earliestMs = Infinity;
  for (const value of upperBounds) {
    const ms = new Date(value).getTime();
    if (!Number.isNaN(ms) && ms < earliestMs) {
      earliestMs = ms;
      earliest = value;
    }
  }
  return earliest;
};

const saml20 = {
  getInResponseTo,
  getSubjectConfirmationInResponseTo,
  getDestination,
  validateRecipient,
  getAssertionId,
  getNotOnOrAfter,
  validateExpiration,
  validateAudience,
  parse,
};

export default saml20;
