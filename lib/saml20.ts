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
  } else if (result instanceof Array) {
    result.forEach(function parseArrayItem(i, ix) {
      result[ix] = getProp(i);
    });

    return { result, format };
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

  return {
    audience: getProp(assertion, 'Conditions.AudienceRestriction.Audience'),
    claims: claims,
    issuer: getProp(assertion, 'Issuer'),
    sessionIndex: getProp(assertion, 'AuthnStatement.@.SessionIndex'),
    assertionId: getAssertionId(assertion),
    notOnOrAfter: getNotOnOrAfter(assertion),
  };
};

const audienceCheck = (audience, expectedAudience, strictValidation) => {
  if (strictValidation) {
    return audience === expectedAudience;
  }

  return audience.startsWith(expectedAudience);
};

const validateAudience = (assertion, realm, strictValidation = false) => {
  const audience = getProp(assertion, 'Conditions.AudienceRestriction.Audience');
  if (audience) {
    try {
      if (Array.isArray(realm)) {
        for (let i = 0; i < realm.length; i++) {
          if (audienceCheck(audience, realm[i], strictValidation)) {
            return true;
          }
        }
        return false;
      }
      return audienceCheck(audience, realm, strictValidation);
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (err) {
      return false;
    }
  } else {
    return false;
  }
};

const clockSkewMs = 10 * 60 * 1000; // 10 minutes clock skew.

// Collect every SubjectConfirmationData element across all SubjectConfirmation
// entries. Bearer assertions carry their expiration here rather than (or in
// addition to) Conditions.
const getSubjectConfirmationData = (assertion): Record<string, unknown>[] => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let confirmations = getAttribute<any>(assertion, 'Subject.SubjectConfirmation');
  if (!confirmations) {
    return [];
  }
  confirmations = Array.isArray(confirmations) ? confirmations : [confirmations];
  const data: Record<string, unknown>[] = [];
  for (const confirmation of confirmations) {
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
  // The <Conditions> window is an absolute constraint on the assertion: when
  // present it must be satisfied. A present-but-unparseable bound is invalid.
  const conditionsNotBefore = getAttribute<string | undefined>(assertion, 'Conditions.@.NotBefore');
  const conditionsNotOnOrAfter = getAttribute<string | undefined>(assertion, 'Conditions.@.NotOnOrAfter');
  const conditionsResult = checkWindow(conditionsNotBefore, conditionsNotOnOrAfter);
  if (conditionsResult === 'invalid') {
    return false;
  }

  // When <Conditions> supplies a satisfied upper bound, the assertion is
  // time-boxed and currently within its validity window.
  if (conditionsResult === 'valid') {
    return true;
  }

  // Otherwise fall back to the bearer SubjectConfirmationData. Per SAML 2.0
  // core (2.4.1.1) multiple SubjectConfirmation elements are alternatives:
  // satisfying any one is sufficient. The assertion is valid if at least one
  // confirmation is currently within its window AND carries an upper bound.
  // If no satisfied upper bound exists anywhere, the assertion is rejected
  // rather than treated as "never expires" (the original NaN defect).
  for (const scd of getSubjectConfirmationData(assertion)) {
    const attrs = (scd['@'] as Record<string, string> | undefined) ?? {};
    if (checkWindow(attrs.NotBefore, attrs.NotOnOrAfter) === 'valid') {
      return true;
    }
  }

  return false;
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

const getAssertionId = (assertion): string | undefined => {
  return getAttribute<string | undefined>(assertion, '@.ID');
};

// The effective NotOnOrAfter after which the assertion can no longer validate,
// mirroring validateExpiration: the absolute Conditions/@NotOnOrAfter when
// present, otherwise the latest bearer SubjectConfirmationData/@NotOnOrAfter
// (SubjectConfirmations are alternatives, so the assertion remains usable until
// the last of them lapses). Callers key replay-cache TTLs off this value, so it
// must reflect the real upper bound rather than only the Conditions window.
const getNotOnOrAfter = (assertion): string | undefined => {
  const conditionsNotOnOrAfter = getAttribute<string | undefined>(assertion, 'Conditions.@.NotOnOrAfter');
  if (conditionsNotOnOrAfter) {
    return conditionsNotOnOrAfter;
  }

  let latest: string | undefined;
  let latestMs = -Infinity;
  for (const scd of getSubjectConfirmationData(assertion)) {
    const value = (scd['@'] as Record<string, string> | undefined)?.NotOnOrAfter;
    if (!value) {
      continue;
    }
    const ms = new Date(value).getTime();
    if (!Number.isNaN(ms) && ms > latestMs) {
      latestMs = ms;
      latest = value;
    }
  }
  return latest;
};

const saml20 = {
  getInResponseTo,
  getSubjectConfirmationInResponseTo,
  getAssertionId,
  getNotOnOrAfter,
  validateExpiration,
  validateAudience,
  parse,
};

export default saml20;
