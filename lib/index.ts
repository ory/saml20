'use strict';

import { validateSignature, certToPEM } from './validateSignature';

import { request, parseSAMLRequest, decodeBase64 } from './request';
import { stripCertHeaderAndFooter, PubKeyInfo } from './cert';
import { createSAMLResponse, parse, validate, parseIssuer, WrapError } from './response';
import { parseMetadata, createIdPMetadataXML, createSPMetadataXML } from './metadata';
import { createPostForm } from './post';
import { sign } from './sign';
import { decryptXml } from './decrypt';
import { parseLogoutResponse, createLogoutRequest } from './logout';
import { encryptAssertion, EncryptionAlgorithms } from './encrypt';
import {EncryptOptions, SpMetadataOptions, IdpMetadataOptions, SAMLResponseOptions, SAMLReq, SAMLProfile, SignOptions} from './typings';

export default {
  parseMetadata,
  createIdPMetadataXML,
  createSPMetadataXML,
  createSAMLResponse,
  request,
  parseSAMLRequest,
  decodeBase64,
  parse,
  validate,
  PubKeyInfo,
  certToPEM,
  stripCertHeaderAndFooter,
  createPostForm,
  sign,
  validateSignature,
  decryptXml,
  parseIssuer,
  WrapError,
  parseLogoutResponse,
  createLogoutRequest,
  encryptAssertion: encryptAssertion,
  EncryptionAlgorithms,
};

export type {
  EncryptOptions,
  SpMetadataOptions,
  IdpMetadataOptions,
  SAMLResponseOptions,
  SAMLReq,
  SAMLProfile,
  SignOptions
};
