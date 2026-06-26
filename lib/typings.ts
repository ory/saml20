export interface SAMLReq {
  ssoUrl?: string;
  entityID: string;
  callbackUrl: string;
  isPassive?: boolean;
  forceAuthn?: boolean;
  identifierFormat?: string;
  providerName?: string;
  signingKey: string;
  publicKey: string;
}

export interface SAMLProfile {
  audience: string;
  claims: Record<string, any>;
  issuer: string;
  sessionIndex: string;
  // Signed assertion identifier and validity bound, exposed so callers can
  // implement one-time replay protection keyed by assertionId until notOnOrAfter.
  assertionId?: string;
  notOnOrAfter?: string;
}

// Identifiers from the signed assertion passed to a caller-supplied replay
// validator. The validator returns true when the assertion has already been
// used (a replay) and must be rejected.
export interface AssertionReplayInfo {
  assertionId?: string;
  sessionIndex?: string;
  notOnOrAfter?: string;
  inResponseTo?: string;
}
