import assert from 'assert';
import { xmlToObject } from '../../lib/xml';
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

  it('rejects any other undeclared prefix', function () {
    assert.throws(() => asDollar('<a><p:b/></a>'), /NamespaceError/);
  });

  it('rejects a DTD and a second root element', function () {
    assert.throws(() => asDollar('<!DOCTYPE a><a/>'), doctypeNotAllowedError);
    assert.throws(() => asDollar('<a/><b/>'), multiRootedXMLError);
  });
});
