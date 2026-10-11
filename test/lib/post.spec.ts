import assert from 'assert';
import * as saml from '../../lib/post';

describe('post.ts', function () {
  it('Should validate creation of post form', function (done) {
    const relayState = 'boxyhq_jackson_17b723c56a2fdc4e94f5e5fa792f89e3';
    const samlRequest =
      'PHNhbWxwOkxvZ291dFJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c';
    const postUrl = 'https://auth0.com/samlp';

    const form = saml.createPostForm(postUrl, [
      { name: 'RelayState', value: relayState },
      {
        name: 'SAMLRequest',
        value: samlRequest,
      },
    ]);

    assert.strictEqual(form.includes(`<form method="post" action="${encodeURI(postUrl)}">`), true);
    assert.strictEqual(form.includes(`<input type="hidden" name="RelayState" value="${relayState}"/>`), true);
    assert.strictEqual(
      form.includes(`<input type="hidden" name="SAMLRequest" value="${samlRequest}"/>`),
      true
    );
    assert.strictEqual(form.includes(`<input type="submit" value="Continue" />`), true);
    done();
  });
});

describe('createPostForm escaping and structure', function () {
  it('HTML-escapes field values', function () {
    const form = saml.createPostForm('https://sp.example.com/acs', [
      { name: 'RelayState', value: `"><script>alert('x')</script>&` },
    ]);
    assert(
      form.includes(
        '<input type="hidden" name="RelayState" value="&quot;&gt;&lt;script&gt;alert(&#039;x&#039;)&lt;/script&gt;&amp;"/>'
      )
    );
    assert(!form.includes('<script>alert'));
  });

  it('percent-encodes characters in the action URL that would break the attribute', function () {
    const form = saml.createPostForm('https://sp.example.com/acs?a="b"&c=<d>', []);
    assert(form.includes('<form method="post" action="https://sp.example.com/acs?a=%22b%22&c=%3Cd%3E">'));
  });

  it('renders a form with only the submit button when there are no params', function () {
    for (const params of [[], undefined as unknown as { name: string; value: string }[]]) {
      const form = saml.createPostForm('https://sp.example.com/acs', params);
      assert(!form.includes('type="hidden"'));
      assert(form.includes('<input type="submit" value="Continue" />'));
    }
  });

  it('keeps an empty value empty', function () {
    const form = saml.createPostForm('https://sp.example.com/acs', [{ name: 'RelayState', value: '' }]);
    assert(form.includes('<input type="hidden" name="RelayState" value=""/>'));
  });
});
