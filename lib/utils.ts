import { DOMParser, MIME_TYPE } from '@xmldom/xmldom';
import crypto from 'crypto';

const multiRootedXMLError = new Error('multirooted xml not allowed.');
const doctypeNotAllowedError = new Error('doctype not allowed.');

// Detects a document type definition (DTD) declaration in a raw XML string.
// `parseFromString` rejects a DTD via the parsed `doctype` node, but xml2js/sax
// does not expose one, so its callers screen the raw string with this instead.
// A DOCTYPE has no legitimate place in SAML XML and accepting one is an
// XXE-class risk. See https://github.com/ory/polis/issues/4071.
//
// A DTD is introduced by `<!DOCTYPE` and may only contain `<!ENTITY`/`<!ELEMENT`
// declarations, so the presence of any of these keywords means the document
// carries a DTD. Detection is a single keyword search anywhere in the raw
// string: it is linear (a fixed alternation with no backtracking) and cannot be
// evaded. We deliberately do NOT try to ignore the keyword when it appears
// inside a comment, CDATA section or processing instruction. Doing so requires
// reproducing the parser's lenient error-recovery tokenizer, and every attempt
// has been bypassable: a malformed prefix such as `<!<!-->` makes a hand-rolled
// scanner treat the real `<!DOCTYPE` as comment content (optionally closed by an
// attacker-supplied trailing `-->`), while sax still processes the DTD. The keyword
// is matched without requiring trailing whitespace because sax enters its doctype
// state on the bare keyword (e.g. `<!DOCTYPERoot ...>`). The only cost is
// rejecting the rare, malformed document that embeds the literal keyword as data;
// that fails safe, and well-formed XML cannot carry a raw `<` as text (it must be
// escaped), so a false positive is only possible inside a comment or CDATA.
// See https://github.com/ory/polis/issues/4071.
const dtdDeclaration = /<!DOCTYPE|<!ENTITY|<!ELEMENT/i;

const containsDoctype = (xml: string): boolean => dtdDeclaration.test(xml);

const countRootNodes = (xmlDoc: Document) => {
  const rootNodes = Array.from(xmlDoc.childNodes as NodeListOf<Element>).filter(
    (n) => n.tagName != null && n.childNodes != null
  );
  return rootNodes.length;
};

const parseFromString = (xmlString: string) => {
  // Reject a DTD before the parser processes it. Checking only the parsed
  // `doctype` node (below) lets a malformed DTD make @xmldom/xmldom throw first,
  // leaking raw parser text (e.g. "doctype not terminated with > at position N")
  // instead of the fixed error. See https://github.com/ory/polis/issues/4071.
  if (containsDoctype(xmlString)) {
    throw doctypeNotAllowedError;
  }

  const errors: string[] = [];
  let multiRootErrFound = false;
  const onError = (level, msg) => {
    if (isMultiRootedXMLError({ message: msg })) {
      if (!multiRootErrFound) {
        multiRootErrFound = true;
        errors.push(msg);
      }
    } else if (level !== 'warn') {
      if (msg.indexOf('entity not matching Reference production:') < 0) {
        errors.push(msg);
      }
    }
  };
  try {
    const xml = new DOMParser({ onError }).parseFromString(xmlString, MIME_TYPE.XML_APPLICATION);

    // SAML XML never legitimately declares a document type definition (DTD).
    // Accepting one exposes the parser to XXE-class attacks: a DTD can declare
    // entities and its handling makes parser behaviour observable as an oracle.
    // Reject any document that declares a DOCTYPE. See
    // https://github.com/ory/polis/issues/4071.
    if (xml.doctype) {
      throw doctypeNotAllowedError;
    }

    if (multiRootErrFound) {
      throw multiRootedXMLError;
    } else if (errors.length > 0) {
      throw new Error('Invalid XML.');
    }

    // @ts-expect-error missing Node properties are not needed
    const rootNodeCount = countRootNodes(xml);
    if (rootNodeCount > 1) {
      throw multiRootedXMLError;
    }

    if (rootNodeCount === 0) {
      throw new Error('Invalid assertion.');
    }

    return xml;
  } catch (err) {
    if (isMultiRootedXMLError(err)) {
      throw multiRootedXMLError;
    } else {
      throw err;
    }
  }
};

const thumbprint = (cert: string) => {
  const shasum = crypto.createHash('sha1');
  const bin = Buffer.from(cert, 'base64').toString('binary');
  shasum.update(bin);
  return shasum.digest('hex');
};

const getAttribute = <TDefault = unknown>(value: any, path: string, defaultValue?: TDefault): TDefault => {
  const segments = path.split(/[\.\[\]]/g); // eslint-disable-line no-useless-escape
  let current: any = value;
  for (const key of segments) {
    if (current === null) return defaultValue as TDefault;
    if (current === undefined) return defaultValue as TDefault;
    const dequoted = key.replace(/['"]/g, '');
    if (dequoted.trim() === '') continue;
    current = current[dequoted];
  }
  if (current === undefined) return defaultValue as TDefault;
  return current;
};

const isMultiRootedXMLError = (err: any) => {
  if ((err as any)?.message?.indexOf('Only one element can be added and only after doctype') >= 0) {
    return true;
  }
  return false;
};

export {
  parseFromString,
  thumbprint,
  getAttribute,
  isMultiRootedXMLError,
  multiRootedXMLError,
  doctypeNotAllowedError,
  containsDoctype,
};
