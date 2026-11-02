import { describe, it } from 'node:test';
import assert from 'node:assert';
import { xmlToObject, buildXml } from '../../lib/xml';
import { doctypeNotAllowedError, multiRootedXMLError } from '../../lib/utils';

const asDollar = (xml: string) => xmlToObject(xml, { attrkey: '$' });
const collapsed = (xml: string) => xmlToObject(xml, { attrkey: '@', collapse: true });

describe('xmlToObject', function () {
  it('returns null for an empty or whitespace-only document', function () {
    assert.strictEqual(asDollar(''), null);
    assert.strictEqual(asDollar('  \n '), null);
  });

  it('strips namespace prefixes from tag names but not from attribute names', function () {
    assert.deepStrictEqual(asDollar('<p:a xmlns:p="urn:p"><p:b p:c="1"/></p:a>'), {
      a: { $: { 'xmlns:p': 'urn:p' }, b: [{ $: { 'p:c': '1' } }] },
    });
  });

  it('returns a string for an element that has only text', function () {
    assert.deepStrictEqual(asDollar('<a><b>x</b></a>'), { a: { b: ['x'] } });
    assert.deepStrictEqual(asDollar('<a>&amp;&lt;&#65;</a>'), { a: '&<A' });
  });

  it('keeps text under _ next to attributes or child elements', function () {
    assert.deepStrictEqual(asDollar('<a b="1">x</a>'), { a: { $: { b: '1' }, _: 'x' } });
    assert.deepStrictEqual(asDollar('<a>x<c/>y</a>'), { a: { _: 'xy', c: [''] } });
  });

  it('drops whitespace-only text unless it came from CDATA', function () {
    assert.deepStrictEqual(asDollar('<a b="1"> </a>'), { a: { $: { b: '1' } } });
    assert.deepStrictEqual(asDollar('<a> <c/> </a>'), { a: { c: [''] } });
    assert.deepStrictEqual(asDollar('<a b="1"><![CDATA[ ]]></a>'), { a: { $: { b: '1' }, _: ' ' } });
    assert.deepStrictEqual(asDollar('<a><![CDATA[x]]>y</a>'), { a: 'xy' });
  });

  it('returns the whitespace itself for an element with nothing else', function () {
    assert.deepStrictEqual(asDollar('<a><b/><c>\n </c></a>'), { a: { b: [''], c: ['\n '] } });
  });

  it('ignores comments and processing instructions', function () {
    assert.deepStrictEqual(asDollar('<a><!-- c -->x<?pi y?></a>'), { a: 'x' });
  });

  it('lists every child element under its name', function () {
    assert.deepStrictEqual(asDollar('<a><b>1</b><c/><b>2</b></a>'), { a: { b: ['1', '2'], c: [''] } });
  });

  describe('names that Object.prototype also defines', function () {
    // JSON.parse makes "__proto__" an own key; an object literal would set the
    // prototype instead.
    const own = (json: string) => JSON.parse(json);
    const names = ['constructor', 'toString', 'hasOwnProperty', 'valueOf', '__proto__'];

    it('lists child elements with those names as own properties', function () {
      for (const name of names) {
        const xml = `<a xmlns:e="urn:e"><e:${name}>x</e:${name}><e:${name}>y</e:${name}></a>`;
        assert.deepStrictEqual(
          asDollar(xml),
          own(`{"a":{"$":{"xmlns:e":"urn:e"},"${name}":["x","y"]}}`),
          name
        );
        assert.deepStrictEqual(
          collapsed(xml),
          own(`{"a":{"@":{"xmlns:e":"urn:e"},"${name}":["x","y"]}}`),
          name
        );
      }
    });

    it('collapses a single child element with one of those names', function () {
      for (const name of names) {
        const xml = `<a><${name}>x</${name}></a>`;
        assert.deepStrictEqual(collapsed(xml), own(`{"a":{"${name}":"x"}}`), name);
      }
    });

    it('keeps attributes with those names as own properties', function () {
      for (const name of names) {
        assert.deepStrictEqual(asDollar(`<a ${name}="v"/>`), own(`{"a":{"$":{"${name}":"v"}}}`), name);
      }
    });

    it('accepts a root element with one of those names', function () {
      for (const name of names) {
        assert.deepStrictEqual(asDollar(`<${name}>x</${name}>`), own(`{"${name}":"x"}`), name);
      }
    });

    it('never changes the prototype of the objects it returns', function () {
      const result = asDollar('<a __proto__="v"><__proto__ x="1"/></a>') as Record<
        string,
        Record<string, unknown>
      >;
      assert.strictEqual(Object.getPrototypeOf(result.a), Object.prototype);
      assert.strictEqual(Object.getPrototypeOf(result.a.$), Object.prototype);
    });
  });

  describe('with collapse', function () {
    it('stores a child that occurs once as the value itself', function () {
      assert.deepStrictEqual(collapsed('<a><b c="1"><d>x</d></b></a>'), {
        a: { b: { '@': { c: '1' }, d: 'x' } },
      });
    });

    it('keeps a list for a child that occurs more than once', function () {
      assert.deepStrictEqual(collapsed('<a><b>1</b><b>2</b></a>'), { a: { b: ['1', '2'] } });
    });

    it("keeps a single empty child element as ['']", function () {
      assert.deepStrictEqual(collapsed('<a><b/></a>'), { a: { b: [''] } });
    });
  });

  it('applies XML line-ending and attribute-value normalization', function () {
    assert.deepStrictEqual(asDollar('<a b="x\r\ny\tz">1\r\n2\r3</a>'), {
      a: { $: { b: 'x y z' }, _: '1\n2\n3' },
    });
  });

  it('strips a byte order mark', function () {
    assert.deepStrictEqual(asDollar('\uFEFF<a>x</a>'), { a: 'x' });
  });

  it('accepts an XML declaration after leading whitespace or comments', function () {
    assert.deepStrictEqual(asDollar('\n  <?xml version="1.0"?>\n<a>x</a>'), { a: 'x' });
    assert.deepStrictEqual(asDollar('\uFEFF\n<?xml version="1.0"?><a>x</a>'), { a: 'x' });
    assert.deepStrictEqual(asDollar('<!-- note -->\n<?xml version="1.0" encoding="UTF-8"?>\n<a>x</a>'), {
      a: 'x',
    });
  });

  it('scans many leading comments without backtracking', function () {
    // Each comment can only end at its own "-->"; a pattern that let one
    // comment run on into the next took exponential time here.
    assert.deepStrictEqual(asDollar('<!--a-->'.repeat(40) + '<a>x</a>'), { a: 'x' });
  });

  it('accepts the xsi and xs prefixes without a declaration', function () {
    assert.deepStrictEqual(asDollar('<a><b xsi:type="xs:string">x</b></a>'), {
      a: { b: [{ $: { 'xsi:type': 'xs:string' }, _: 'x' }] },
    });
  });

  it('accepts the standard SAML prefixes without a declaration', function () {
    const fragment =
      '<md:EntityDescriptor entityID="https://idp"><md:IDPSSODescriptor><md:KeyDescriptor use="signing">' +
      '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
      '</md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>';
    assert.deepStrictEqual(asDollar(fragment), {
      EntityDescriptor: {
        $: { entityID: 'https://idp' },
        IDPSSODescriptor: [
          {
            KeyDescriptor: [
              { $: { use: 'signing' }, KeyInfo: [{ X509Data: [{ X509Certificate: ['MIIB'] }] }] },
            ],
          },
        ],
      },
    });
    assert.deepStrictEqual(asDollar('<samlp:Response><saml:Issuer>i</saml:Issuer></samlp:Response>'), {
      Response: { Issuer: ['i'] },
    });
  });

  it('accepts any undeclared prefix, on elements and attributes alike', function () {
    assert.deepStrictEqual(asDollar('<a><p:b q:r="1">x</p:b></a>'), {
      a: { b: [{ $: { 'q:r': '1' }, _: 'x' }] },
    });
    assert.deepStrictEqual(asDollar('<wsfed:Envelope><wsfed:Body>x</wsfed:Body></wsfed:Envelope>'), {
      Envelope: { Body: ['x'] },
    });
  });

  it('leaves the xml: prefix to the XML namespace', function () {
    assert.deepStrictEqual(asDollar('<a xml:lang="en">x</a>'), { a: { $: { 'xml:lang': 'en' }, _: 'x' } });
  });

  it('still honours a declared prefix and a declared default namespace', function () {
    assert.deepStrictEqual(asDollar('<p:a xmlns:p="urn:p"><p:b>x</p:b></p:a>'), {
      a: { $: { 'xmlns:p': 'urn:p' }, b: ['x'] },
    });
    assert.deepStrictEqual(asDollar('<a xmlns="urn:d"><b>x</b></a>'), {
      a: { $: { xmlns: 'urn:d' }, b: ['x'] },
    });
  });

  it('rejects a DTD and a second root element', function () {
    assert.throws(() => asDollar('<!DOCTYPE a><a/>'), doctypeNotAllowedError);
    assert.throws(() => asDollar('<a/><b/>'), multiRootedXMLError);
  });

  it('rejects an & that does not start a reference', function () {
    for (const text of ['a & b', 'a &', 'a&;b', 'a&b', 'a&#;b', 'a&#xg;b', 'a&#X26;b', 'a&-;b']) {
      assert.throws(() => asDollar(`<a>${text}</a>`), /Invalid XML/, text);
      assert.throws(() => asDollar(`<a b="${text}"/>`), /Invalid XML/, text);
    }
  });

  it('accepts references and an & inside CDATA or a comment', function () {
    assert.strictEqual(asDollar('<a>x&amp;y&#38;z&#x26;w</a>')!.a, 'x&y&z&w');
    assert.strictEqual(asDollar('<a>x&lt;&gt;&quot;&apos;</a>')!.a, 'x<>"\'');
    assert.strictEqual(asDollar('<a><![CDATA[a & b]]></a>')!.a, 'a & b');
    assert.strictEqual(asDollar('<a><!-- a & b -->c</a>')!.a, 'c');
  });
});

describe('buildXml', function () {
  const nodes = {
    'a:root': {
      '@xmlns:a': 'urn:a',
      '@n': 1,
      '@f': false,
      'a:child': [{ '#text': 'x & <y>' }, { '@q': '"' }],
    },
  };

  it('serializes attributes, text and repeated elements with a declaration', function () {
    assert.strictEqual(
      buildXml(nodes),
      '<?xml version="1.0"?><a:root xmlns:a="urn:a" n="1" f="false"><a:child>x &amp; &lt;y&gt;</a:child><a:child q="&quot;"/></a:root>'
    );
  });

  it('writes the encoding and standalone values and pretty-prints on request', function () {
    assert.strictEqual(
      buildXml({ a: { b: { '#text': 't' } } }, { encoding: 'UTF-8', standalone: false, pretty: true }),
      '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n<a>\n  <b>t</b>\n</a>'
    );
    assert.strictEqual(
      buildXml({ a: {} }, { encoding: 'UTF-8' }),
      '<?xml version="1.0" encoding="UTF-8"?><a/>'
    );
  });

  it('escapes a carriage return so the parser does not normalize it away', function () {
    assert.strictEqual(
      buildXml({ a: { '@x': 'p\rq', '#text': 'r\rs' } }),
      '<?xml version="1.0"?><a x="p&#xD;q">r&#xD;s</a>'
    );
  });

  it('rejects a character XML cannot carry', function () {
    assert.throws(() => buildXml({ a: { '#text': 'a\u0001b' } }), /Invalid character/);
    assert.throws(() => buildXml({ a: { '#text': 'a\ud800b' } }), /Invalid character/);
    assert.throws(() => buildXml({ a: { '@x': 'a\u0000b' } }), /Invalid character/);
    assert.strictEqual(
      buildXml({ a: { '#text': 'tab\t\u00e9\u{1F600}' } }),
      '<?xml version="1.0"?><a>tab\t\u00e9\u{1F600}</a>'
    );
  });
});
