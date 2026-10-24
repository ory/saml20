import { validateSignature, DEFAULT_MAX_SIGNATURE_REFERENCES } from './validateSignature';
import type { ValidateSignatureOptions } from './validateSignature';

import {
  request,
  parseSAMLRequest,
  decodeBase64,
  samlRequestTooLargeError,
  samlRequestDecodeError,
  MAX_ENCODED_REQUEST_LENGTH,
  MAX_INFLATED_REQUEST_BYTES,
} from './request';
import type { DecodeBase64Options } from './request';
import { stripCertHeaderAndFooter, certToPEM } from './cert';
import { createSAMLResponse, validate, parseIssuer, WrapError } from './response';
import { parseMetadata, createIdPMetadataXML, createSPMetadataXML } from './metadata';
import { createPostForm } from './post';
import { sign } from './sign';
import { containsDoctype } from './utils';
import { parseLogoutResponse, createLogoutRequest, parseLogoutRequest, createLogoutResponse } from './logout';
import type {
  ParsedLogoutResponse,
  LogoutRequestParams,
  ParsedLogoutRequest,
  LogoutResponseParams,
} from './logout';

export default {
  parseMetadata,
  createIdPMetadataXML,
  createSPMetadataXML,
  createSAMLResponse,
  request,
  parseSAMLRequest,
  decodeBase64,
  samlRequestTooLargeError,
  samlRequestDecodeError,
  MAX_ENCODED_REQUEST_LENGTH,
  MAX_INFLATED_REQUEST_BYTES,
  validate,
  certToPEM,
  stripCertHeaderAndFooter,
  createPostForm,
  sign,
  validateSignature,
  DEFAULT_MAX_SIGNATURE_REFERENCES,
  parseIssuer,
  WrapError,
  containsDoctype,
  parseLogoutResponse,
  createLogoutRequest,
  parseLogoutRequest,
  createLogoutResponse,
};

// The same API as named exports, for `import { validate } from '@boxyhq/saml20'`.
// The default export stays for existing callers.
export {
  parseMetadata,
  createIdPMetadataXML,
  createSPMetadataXML,
  createSAMLResponse,
  request,
  parseSAMLRequest,
  decodeBase64,
  samlRequestTooLargeError,
  samlRequestDecodeError,
  MAX_ENCODED_REQUEST_LENGTH,
  MAX_INFLATED_REQUEST_BYTES,
  validate,
  certToPEM,
  stripCertHeaderAndFooter,
  createPostForm,
  sign,
  validateSignature,
  DEFAULT_MAX_SIGNATURE_REFERENCES,
  parseIssuer,
  WrapError,
  containsDoctype,
  parseLogoutResponse,
  createLogoutRequest,
  parseLogoutRequest,
  createLogoutResponse,
};

export type { SAMLProfile, SAMLReq, AssertionReplayInfo, ValidateOptions, AssertedNameID } from './typings';
export type { ParseMetadataOptions, ParsedMetadata, MetadataEndpoints } from './metadata';

export type {
  ParsedLogoutResponse,
  LogoutRequestParams,
  ParsedLogoutRequest,
  LogoutResponseParams,
  ValidateSignatureOptions,
  DecodeBase64Options,
};
