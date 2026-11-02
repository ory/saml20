import { parseFromString, setOwn } from './utils';

type XmlObjectOptions = {
  // Key that holds an element's attributes.
  attrkey: '@' | '$';
  // Store a child element that occurs once as the value itself rather than a
  // one-element list. A single empty child element stays a list ([''])
  // because callers rely on that shape.
  collapse?: boolean;
};

const ELEMENT_NODE = 1;
const TEXT_NODE = 3;
const CDATA_SECTION_NODE = 4;

const prefix = /(?!xmlns)^.*:/;
const stripPrefix = (name: string) => name.replace(prefix, '');

// Prefixes a document may use without declaring them, bound to the namespace
// each conventionally means. SAML producers often write xsi:type="xs:string"
// without declaring either prefix, and metadata pasted from a larger document
// can arrive with md:/ds: prefixes and no xmlns attributes at all.
const undeclaredPrefixes = {
  xsi: 'http://www.w3.org/2001/XMLSchema-instance',
  xs: 'http://www.w3.org/2001/XMLSchema',
  md: 'urn:oasis:names:tc:SAML:2.0:metadata',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
  xenc: 'http://www.w3.org/2001/04/xmlenc#',
  mdui: 'urn:oasis:names:tc:SAML:metadata:ui',
  mdattr: 'urn:oasis:names:tc:SAML:metadata:attribute',
  mdrpi: 'urn:oasis:names:tc:SAML:metadata:rpi',
  shibmd: 'urn:mace:shibboleth:metadata:1.0',
  alg: 'urn:oasis:names:tc:SAML:metadata:algsupport',
};

const toObject = (element: Element, options: XmlObjectOptions): unknown => {
  const obj: Record<string, unknown> = {};
  let text = '';
  let cdata = false;

  if (element.attributes.length > 0) {
    const attrs: Record<string, string> = {};
    for (let i = 0; i < element.attributes.length; i++) {
      const attr = element.attributes[i];
      setOwn(attrs, attr.name, attr.value);
    }
    obj[options.attrkey] = attrs;
  }

  const children = new Map<string, unknown[]>();
  for (let node = element.firstChild; node; node = node.nextSibling) {
    if (node.nodeType === ELEMENT_NODE) {
      const name = stripPrefix((node as Element).tagName);
      const values = children.get(name);
      if (values) {
        values.push(toObject(node as Element, options));
      } else {
        children.set(name, [toObject(node as Element, options)]);
      }
    } else if (node.nodeType === TEXT_NODE) {
      text += (node as Text).data;
    } else if (node.nodeType === CDATA_SECTION_NODE) {
      text += (node as CDATASection).data;
      cdata = true;
    }
  }

  const keepText = cdata || !/^\s*$/.test(text);
  if (keepText && Object.keys(obj).length === 0 && children.size === 0) {
    return text;
  }
  if (keepText) {
    obj._ = text;
  }
  for (const [name, values] of children) {
    setOwn(obj, name, options.collapse && values.length === 1 && values[0] ? values[0] : values);
  }
  return Object.keys(obj).length === 0 ? text : obj;
};

// An XML declaration is only allowed as the very first thing in a document,
// but hand-edited metadata often has a newline or a comment before it.
const misplacedDeclaration = /^((?:\s|<!--(?:(?!-->)[\s\S])*-->)+)<\?xml(?=\s)[\s\S]*?\?>/;

// Parses XML with parseFromString, which rejects DTDs and multiple roots, into
// plain objects: tag names without their namespace prefix, attributes under
// `attrkey`, text under `_`, child elements in lists under their name, and a
// string for an element that has only text. Returns null for an empty document.
const xmlToObject = (xml: string, options: XmlObjectOptions): Record<string, unknown> | null => {
  xml = xml.replace(/^\uFEFF/, '').replace(misplacedDeclaration, '$1');
  if (xml.trim() === '') {
    return null;
  }
  const root = parseFromString(xml, undeclaredPrefixes).documentElement as unknown as Element;
  const result: Record<string, unknown> = {};
  setOwn(result, stripPrefix(root.tagName), toObject(root, options));
  return result;
};

export { xmlToObject };
export type { XmlObjectOptions };
