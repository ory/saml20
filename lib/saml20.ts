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

const validateExpiration = (assertion) => {
  const dteNotBefore = getProp(assertion, 'Conditions.@.NotBefore');
  let notBefore: any = new Date(dteNotBefore);
  notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10); // 10 minutes clock skew

  const dteNotOnOrAfter = getProp(assertion, 'Conditions.@.NotOnOrAfter');
  let notOnOrAfter: any = new Date(dteNotOnOrAfter);
  notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10); // 10 minutes clock skew

  const now = new Date();
  return !(now < notBefore || now > notOnOrAfter);
};

const getInResponseTo = (xml) => {
  return getProp(xml, 'Response.@.InResponseTo');
};

const saml20 = { getInResponseTo, validateExpiration, validateAudience, parse };

export default saml20;
