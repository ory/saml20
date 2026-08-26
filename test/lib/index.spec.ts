import assert from 'assert';
import { default as saml } from '../../lib/index';

// Locks the public API surface consumers rely on. containsDoctype is exported so
// callers (e.g. Ory Polis) can reject a DTD before their own XML parsing instead
// of duplicating the check. See https://github.com/ory/polis/issues/4071.
describe('index.ts', function () {
  it('should expose containsDoctype on the default export', function () {
    assert.strictEqual(typeof saml.containsDoctype, 'function');
  });

  it('containsDoctype should detect a real DOCTYPE and ignore inert regions', function () {
    assert.strictEqual(saml.containsDoctype('<!DOCTYPE r><r/>'), true);
    assert.strictEqual(saml.containsDoctype('<root><![CDATA[<!DOCTYPE x>]]></root>'), false);
  });
});
