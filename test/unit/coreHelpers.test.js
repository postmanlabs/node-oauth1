var expect = require('chai').expect;

function runSuite(name, OAuth) {
    describe('[' + name + '] Core helpers', function () {
        describe('percentEncode / decodePercent', function () {
            it('should percent-encode special characters per OAuth spec', function () {
                var input = "!*'()~abc-_.",
                    encoded = OAuth.percentEncode(input);

                expect(encoded).to.equal('%21%2A%27%28%29~abc-_.');
            });

            it('should decode plus as space for x-www-form-urlencoded', function () {
                expect(OAuth.decodePercent('a+b+c')).to.equal('a b c');
            });

            it('should encode array items joined by &', function () {
                var encoded = OAuth.percentEncode(['a b', '!*']);
                expect(encoded).to.equal('a%20b&%21%2A');
            });

            it('should return empty string for null/undefined', function () {
                expect(OAuth.percentEncode(null)).to.equal('');
                expect(OAuth.percentEncode(undefined)).to.equal('');
            });
            
            it('decodePercent should handle null input', function () {
                expect(OAuth.decodePercent(null)).to.equal('null');
            });
        });

        describe('getParameterList / getParameterMap / getParameter', function () {
            it('should convert object to list and map correctly', function () {
                var obj = { a: '1', b: '2' },
                    list = OAuth.getParameterList(obj),
                    map = OAuth.getParameterMap(list);

                expect(list).to.deep.include.members([['a', '1'], ['b', '2']]);
                expect(map).to.deep.equal({ a: '1', b: '2' });
                expect(OAuth.getParameter(list, 'a')).to.equal('1');
                expect(OAuth.getParameter(obj, 'b')).to.equal('2');
            });

            it('should decode form strings to list', function () {
                var list = OAuth.getParameterList('x=1&y=2');
                expect(list).to.deep.equal([['x', '1'], ['y', '2']]);
            });

            it('getParameterMap should pick first value for duplicate keys', function () {
                var list = [['a', '1'], ['a', '2'], ['b', '3']],
                    map = OAuth.getParameterMap(list);
                expect(map.a).to.equal('1');
                expect(map.b).to.equal('3');
            });

            it('getParameterList should return array as-is', function () {
                var arr = [['a', '1']];
                expect(OAuth.getParameterList(arr)).to.equal(arr);
            });

            it('getParameterMap should parse string input', function () {
                var map = OAuth.getParameterMap('a=1&b=2');
                expect(map).to.deep.equal({ a: '1', b: '2' });
            });
        });

        describe('formEncode / decodeForm', function () {
            it('should encode parameters to query-string', function () {
                var qs = OAuth.formEncode([['a', '1'], ['b', '2']]);
                expect(qs).to.equal('a=1&b=2');
            });

            it('should decode query-string to parameter list', function () {
                var list = OAuth.decodeForm('a=1&b=2');
                expect(list).to.deep.equal([['a', '1'], ['b', '2']]);
            });
        });

        describe('setParameter / setParameters', function () {
            it('should set, update and delete parameters in array form', function () {
                var msg = { parameters: [['a', '1']] };
                OAuth.setParameter(msg, 'b', '2');
                expect(msg.parameters).to.deep.include.members([['a', '1'], ['b', '2']]);

                OAuth.setParameter(msg, 'a', '3');
                var aValue = msg.parameters.find(function (p) { return p[0] === 'a'; })[1];
                expect(aValue).to.equal('3');

                OAuth.setParameter(msg, 'b', undefined);
                expect(msg.parameters.some(function (p) { return p[0] === 'b'; })).to.equal(false);
            });

            it('should set parameters in map form', function () {
                var msg = { parameters: { a: '1' } };
                OAuth.setParameter(msg, 'b', '2');
                expect(msg.parameters).to.deep.equal({ a: '1', b: '2' });
            });

            it('should apply a list via setParameters', function () {
                var msg = { parameters: { } };
                OAuth.setParameters(msg, [['x', '1'], ['y', '2']]);
                expect(msg.parameters).to.deep.equal({ x: '1', y: '2' });
            });
        });

        describe('addToURL', function () {
            it('should append ? when no query present', function () {
                expect(OAuth.addToURL('https://example.com/path', [['a', '1']]))
                    .to.equal('https://example.com/path?a=1');
            });

            it('should append & when query present', function () {
                expect(OAuth.addToURL('https://example.com/path?x=9', [['a', '1']]))
                    .to.equal('https://example.com/path?x=9&a=1');
            });
        });

        describe('normalizeParameters', function () {
            it('should sort and percent-encode, excluding oauth_signature', function () {
                var normalized = OAuth.SignatureMethod.normalizeParameters([
                    ['b', '2'],
                    ['a', '!'],
                    ['oauth_signature', 'ignored']
                ]);
                expect(normalized).to.equal('a=%21&b=2');
            });

            it('should include duplicate pairs and exercise equality branch', function () {
                var normalized = OAuth.SignatureMethod.normalizeParameters([
                    ['a', '1'], ['a', '1']
                ]);
                expect(normalized).to.equal('a=1&a=1');
            });

            it('should return empty string on null parameters', function () {
                expect(OAuth.SignatureMethod.normalizeParameters(null)).to.equal('');
            });
        });

        describe('parseUri / normalizeUrl', function () {
            it('should drop default ports and lowercase scheme/authority', function () {
                var normalized = OAuth.SignatureMethod.normalizeUrl('HTTP://EXAMPLE.com:80');
                expect(normalized).to.equal('http://example.com/');
            });

            it('should preserve non-default port', function () {
                var normalized = OAuth.SignatureMethod.normalizeUrl('https://example.com:8443/path');
                expect(normalized).to.equal('https://example.com:8443/path');
            });

            it('should drop default https port and remove query/fragment', function () {
                var normalized = OAuth.SignatureMethod.normalizeUrl('https://example.com:443/path?q=1#frag');
                expect(normalized).to.equal('https://example.com/path');
            });
        });

        describe('getBaseString', function () {
            it('should build correct base string with query and params', function () {
                var message = {
                    method: 'get',
                    action: 'https://api.example.com/r?a=1',
                    parameters: [['b', '2']]
                };
                var base = OAuth.SignatureMethod.getBaseString(message);
                expect(base).to.equal(
                    'GET&https%3A%2F%2Fapi.example.com%2Fr&' +
                    'a%3D1%26b%3D2'
                );
            });

            it('should build base string when URL has no path and no query', function () {
                var message = { method: 'post', action: 'https://example.com', parameters: [] };
                var base = OAuth.SignatureMethod.getBaseString(message);
                expect(base).to.equal('POST&https%3A%2F%2Fexample.com%2F&');
            });

            it('should percent-encode parameter names and values', function () {
                var message = {
                    method: 'get',
                    action: 'https://e.com/r',
                    parameters: [['na me', "!*"]]
                };
                var base = OAuth.SignatureMethod.getBaseString(message);
                expect(base).to.equal('GET&https%3A%2F%2Fe.com%2Fr&na%2520me%3D%2521%252A');
            });
        });

        describe('completeRequest / setTimestampAndNonce', function () {
            var origTs = OAuth.timestamp,
                origNonce = OAuth.nonce;

            afterEach(function () {
                OAuth.timestamp = origTs;
                OAuth.nonce = origNonce;
            });

            it('should populate defaults and sign with HMAC-SHA1 by default', async function () {
                OAuth.timestamp = function () { return '1588771035'; };
                OAuth.nonce = function () { return 'baz'; };

                var message = {
                    action: 'https://postman.com/path',
                    method: 'GET',
                    parameters: { oauth_consumer_key: 'foo', oauth_token: 'bar' }
                };
                var accessor = { consumerSecret: 'alpha', tokenSecret: 'beta' };

                await OAuth.completeRequest(message, accessor);

                expect(message.parameters.oauth_version).to.equal('1.0');
                expect(message.parameters.oauth_timestamp).to.equal('1588771035');
                expect(message.parameters.oauth_nonce).to.equal('baz');
                expect(message.parameters.oauth_signature_method).to.equal('HMAC-SHA1');
                expect(message.parameters.oauth_signature).to.equal('kst31ZZPywC/vi+UVOU93hgdEMg=');
            });

            it('should set timestamp and nonce explicitly', function () {
                var message = { parameters: {} };
                OAuth.timestamp = function () { return '1'; };
                OAuth.nonce = function () { return 'abc'; };
                OAuth.setTimestampAndNonce(message);
                expect(message.parameters.oauth_timestamp).to.equal('1');
                expect(message.parameters.oauth_nonce).to.equal('abc');
            });

            it('should not override provided timestamp/nonce', async function () {
                OAuth.timestamp = function () { return 'X'; };
                OAuth.nonce = function () { return 'Y'; };
                var message = { method: undefined, action: 'https://postman.com/path', parameters: { oauth_timestamp: '1', oauth_nonce: 'n', oauth_consumer_key: 'foo', oauth_token: 'bar' } };
                await OAuth.completeRequest(message, { consumerSecret: 'alpha', tokenSecret: 'beta' });
                expect(message.parameters.oauth_timestamp).to.equal('1');
                expect(message.parameters.oauth_nonce).to.equal('n');
            });

            it('should set timestamp and nonce in array parameters form', function () {
                OAuth.timestamp = function () { return '2'; };
                OAuth.nonce = function () { return 'z'; };
                var message = { parameters: [] };
                OAuth.setTimestampAndNonce(message);
                var params = OAuth.getParameterMap(message.parameters);
                expect(params.oauth_timestamp).to.equal('2');
                expect(params.oauth_nonce).to.equal('z');
            });

            it('should set consumer key and token from accessor when missing', async function () {
                OAuth.timestamp = function () { return '1588771035'; };
                OAuth.nonce = function () { return 'baz'; };
                var message = {
                    action: 'https://postman.com/path',
                    method: 'GET',
                    parameters: { }
                };
                await OAuth.completeRequest(message, { consumerKey: 'foo', token: 'bar', consumerSecret: 'alpha', tokenSecret: 'beta' });
                var params = OAuth.getParameterMap(message.parameters);
                expect(params.oauth_consumer_key).to.equal('foo');
                expect(params.oauth_token).to.equal('bar');
            });

            it('should default oauth_consumer_key to empty string if absent', async function () {
                OAuth.timestamp = function () { return '1588771035'; };
                OAuth.nonce = function () { return 'baz'; };
                var message = {
                    action: 'https://postman.com/path',
                    method: 'GET',
                    parameters: { }
                };
                await OAuth.completeRequest(message, { consumerSecret: 'alpha', tokenSecret: 'beta' });
                var params = OAuth.getParameterMap(message.parameters);
                expect(params.oauth_consumer_key).to.equal('');
                expect(params.oauth_token).to.equal(undefined);
            });

            it('should not override provided oauth_version', async function () {
                OAuth.timestamp = function () { return '1588771035'; };
                OAuth.nonce = function () { return 'baz'; };
                var message = {
                    action: 'https://postman.com/path',
                    method: 'GET',
                    parameters: { oauth_version: '1.0' }
                };
                await OAuth.completeRequest(message, { consumerKey: 'foo', token: 'bar', consumerSecret: 'alpha', tokenSecret: 'beta' });
                expect(message.parameters.oauth_version).to.equal('1.0');
            });
        });

        describe('declareClass property merge', function () {
            it('should copy non-prototype properties from previous to new constructor', function () {
                var previous = { someStatic: 'value' },
                    name = 'TestClassMerge';
                OAuth[name] = previous;
                var Ctor = function () {};
                OAuth.declareClass(OAuth, name, Ctor);
                expect(Ctor.someStatic).to.equal('value');
                delete OAuth[name];
            });
        });

        describe('decodeForm edge cases', function () {
            it('should handle entry without equals as null value', function () {
                var list = OAuth.decodeForm('a&b=2');
                expect(list).to.deep.equal([['a', null], ['b', '2']]);
            });

            it('should ignore empty segments', function () {
                var list = OAuth.decodeForm('a=1&&b=2');
                expect(list).to.deep.equal([['a', '1'], ['b', '2']]);
            });
        });

        describe('formEncode edge cases', function () {
            it('should encode null value as empty assignment', function () {
                expect(OAuth.formEncode([['a', null]])).to.equal('a=');
            });
        });

        describe('getParameterList / Map null inputs', function () {
            it('should return [] for null list and {} for null map', function () {
                expect(OAuth.getParameterList(null)).to.deep.equal([]);
                expect(OAuth.getParameterMap(null)).to.deep.equal({});
            });

            it('getParameter should return null if not present', function () {
                expect(OAuth.getParameter([['a', '1']], 'x')).to.equal(null);
                expect(OAuth.getParameter({ a: '1' }, 'x')).to.equal(undefined);
            });
        });

        describe('setParameter map undefined value', function () {
            it('should set key to undefined in map form', function () {
                var msg = { parameters: {} };
                OAuth.setParameter(msg, 'x', undefined);
                expect(Object.prototype.hasOwnProperty.call(msg.parameters, 'x')).to.equal(true);
                expect(msg.parameters.x).to.equal(undefined);
            });
        });

        describe('correctTimestampFromSrc', function () {
            var realDoc = global.document;
            afterEach(function () { global.document = realDoc; });

            it('should update timestamp from last script src query string', function () {
                var nowS = Math.floor(Date.now() / 1000);
                global.document = {
                    getElementsByTagName: function () {
                        return [
                            { src: 'http://example.com/a.js' },
                            { src: 'http://example.com/b.js?oauth_timestamp=' + nowS }
                        ];
                    }
                };
                OAuth.correctTimestampFromSrc();
                var ts = OAuth.timestamp();
                expect(Math.abs(ts - nowS)).to.be.at.most(1);
            });

            it('should early-return when src missing/invalid', function () {
                global.document = { getElementsByTagName: function () { return [{}, { src: '' }]; } };
                OAuth.correctTimestampFromSrc();

                global.document = { getElementsByTagName: function () { return [{ src: 'http://example.com/file.js' }]; } };
                OAuth.correctTimestampFromSrc();

                global.document = { getElementsByTagName: function () { return [{ src: 'http://example.com/file.js?x=1' }]; } };
                OAuth.correctTimestampFromSrc();
            });

            it('should early-return when scripts list is null/empty', function () {
                global.document = { getElementsByTagName: function () { return null; } };
                OAuth.correctTimestampFromSrc();

                global.document = { getElementsByTagName: function () { return []; } };
                OAuth.correctTimestampFromSrc();
            });
        });

        describe('time and nonce utilities', function () {
            var origCorrect = OAuth.correctTimestamp,
                origTimestamp = OAuth.timestamp;

            afterEach(function () {
                OAuth.correctTimestamp = origCorrect;
                OAuth.timestamp = origTimestamp;
            });

            it('should adjust timestamp via correctTimestamp', function () {
                var nowS = Math.floor(Date.now() / 1000);
                OAuth.correctTimestamp(nowS);
                var ts = OAuth.timestamp();
                expect(Math.abs(ts - nowS)).to.be.at.most(1);
            });

            it('nonce should generate requested length with allowed chars', function () {
                var n = OAuth.nonce(12);
                expect(n).to.have.length(12);
                for (var i = 0; i < n.length; i++) {
                    expect(OAuth.nonce.CHARS.indexOf(n[i])).to.be.at.least(0);
                }
            });
        });

        describe('addToURL no-op cases', function () {
            it('should return url unchanged when params empty or null', function () {
                expect(OAuth.addToURL('https://e.com/p', [])).to.equal('https://e.com/p');
                expect(OAuth.addToURL('https://e.com/p', null)).to.equal('https://e.com/p');
            });
        });
    });
}

module.exports = { runSuite };