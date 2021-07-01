var expect = require('chai').expect,
    OAuth = require('../../index');

describe.only('Utility Functions', function () {
    describe('percentEncode()', function () {
        it('should encode with RFC-3986 standards', function () {        
            var stringToEncode = 'this,should-be_encoded123!#encode /these*)',
                encodedString = OAuth.percentEncode(stringToEncode),
                expectedEncodedString = 'this%2Cshould-be_encoded123%21%23encode%20%2Fthese%2A%29';

            expect(encodedString).to.eql(expectedEncodedString);
        });
    });

    describe('decodePercent()', function () {
        it('should decode completely', function () {
            var stringToDecode = 'this%2Cshould-be_encoded123%21%23encode%20%2Fthese%2A%29',
                decodedString = OAuth.decodePercent(stringToDecode),
                expectedDecodedString = 'this,should-be_encoded123!#encode /these*)';

            expect(decodedString).to.eql(expectedDecodedString);
        });
    });

    describe('decodeForm()', function () {
        it('should decode query string as expected', function () {
            var querystringToDecode = 'a=b&c=d,e&f=g',
                decodedQuery = OAuth.decodeForm(querystringToDecode),
                expectedDecodedQuery = [['a', 'b'], ['c', 'd,e'], ['f', 'g']];

            expect(decodedQuery).to.eql(expectedDecodedQuery);
        });

        it('should decode query string as expected with empty keys', function () {
            var querystringToDecode = 'a=b&c=d,e&=bar',
                decodedQuery = OAuth.decodeForm(querystringToDecode),
                expectedDecodedQuery = [['a', 'b'], ['c', 'd,e'], ['', 'bar']];

            expect(decodedQuery).to.eql(expectedDecodedQuery);
        });

        it('should decode query string as expected with empty values', function () {
            var querystringToDecode = 'a=b&c=d,e&empty=',
                decodedQuery = OAuth.decodeForm(querystringToDecode),
                expectedDecodedQuery = [['a', 'b'], ['c', 'd,e'], ['empty', '']];

            expect(decodedQuery).to.eql(expectedDecodedQuery);
        });
    });

    describe('formEncode()', function () {
        it('should encode query string with RFC-3986 standards', function () {
            var queryToFormEncode = 'a=b&c=d,e&f=g!?&h=i-j_',
                encodedForm = OAuth.formEncode(queryToFormEncode),
                expectedEncodedForm = 'a=b&c=d%2Ce&f=g%21%3F&h=i-j_';

            expect(encodedForm).to.eql(expectedEncodedForm);
        });

        it('should encode query string with empty keys', function () {
            var queryToFormEncode = 'a=b&c=d,e&f=g!?&=bar?',
                encodedForm = OAuth.formEncode(queryToFormEncode),
                expectedEncodedForm = 'a=b&c=d%2Ce&f=g%21%3F&=bar%3F';

            expect(encodedForm).to.eql(expectedEncodedForm);
        });

        it('should encode query string with empty values', function () {
            var queryToFormEncode = 'a=b&c=d,e&f=g!?&foo?=',
                encodedForm = OAuth.formEncode(queryToFormEncode),
                expectedEncodedForm = 'a=b&c=d%2Ce&f=g%21%3F&foo%3F=';

            expect(encodedForm).to.eql(expectedEncodedForm);
        });
    });

    describe('Adding Parameters to Message', function () {
        var message = {
            action: 'https://postman.com/path',
            method: 'GET',
            parameters: {
                oauth_signature_method: 'HMAC-SHA1',
                oauth_consumer_key: 'foo',
                oauth_token: 'bar',
                oauth_nonce: '3',
                oauth_timestamp: '123',
                oauth_version: '1.0'
            }
        };

        describe('setParameter()', function () {
            it('should add the parameter to message', function () {
                var newParamKey = 'testKey',
                    newParamValue = 'testValue';

                OAuth.setParameter(message, newParamKey, newParamValue);

                expect(message.parameters).to.include({testKey: 'testValue'});
            });

            it('should add parameter with empty key to message', function () {
                var emptyParamKey = '',
                newParamValue = 'testValue2';

                OAuth.setParameter(message, emptyParamKey, newParamValue);

                expect(message.parameters).to.include({'' : 'testValue2'});
            });
        });

        describe('setParameters()', function () {
            it('should add all the parameters to message', function () {
                var parametersToAdd = [['a', '1'], ['b', '2'], ['c', '3']];

                OAuth.setParameters(message, parametersToAdd);

                expect(message.parameters).to.include({a: '1', b: '2', c: '3'});
            });
        });
    });

    describe('completeRequest()', function () {
        var message = {
            action: 'https://postman.com/path',
            method: 'GET',
            parameters: {
            }
        };

        it('should complete the request with default parameters', function () {
            var accessor = {consumerKey: '123', token: 'abc'};

            OAuth.completeRequest(message, accessor);

            expect(message.parameters).to.include({oauth_consumer_key: '123'});
            expect(message.parameters).to.include({oauth_token: 'abc'});
            expect(message.parameters).to.include({oauth_version: '1.0'});
            expect(message.parameters).to.have.property('oauth_timestamp');
            expect(message.parameters).to.have.property('oauth_nonce');
            expect(message.parameters).to.have.property('oauth_signature');
        });
    });

    describe('getParameterList()', function () {
        it('should return a list of params when a query string is passed', function () {
            var queryString = 'a=b&c=d,e&f=g&foo=123&bar=baz',
                expectedQueryList = [['a', 'b'], ['c', 'd,e'], ['f', 'g'], ['foo', '123'], ['bar', 'baz']],
                queryList = OAuth.getParameterList(queryString);

            expect(queryList).to.eql(expectedQueryList);
        });

        it('should return a list of params when a query object is passed', function () {
            var queryParams = {a: 'b', c: 'd,e', f: 'g', foo: '123', bar: 'baz'},
                expectedQueryList = [['a', 'b'], ['c', 'd,e'], ['f', 'g'], ['foo', '123'], ['bar', 'baz']],
                queryList = OAuth.getParameterList(queryParams);

            expect(queryList).to.eql(expectedQueryList);
        });

        it('should return the same array when an array is passed', function () {
            var expectedQueryList = [['a', 'b'], ['c', 'd,e'], ['f', 'g'], ['foo', '123'], ['bar', 'baz']],
                queryList = OAuth.getParameterList(expectedQueryList);

            expect(queryList).to.eql(expectedQueryList);
        });
    });
});
