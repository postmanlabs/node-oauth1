var expect = require('chai').expect,
    getBaseString = require('../../index').SignatureMethod.getBaseString;

describe('SignatureMethod.getBaseString()', function () {
    describe('should generate correct base string', function () {
        const baseString = 'GET&https%3A%2F%2Fpostman.com%2Fpath&oauth_consumer_key%3Dfoo%26oauth_nonce%3D3%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D123%26oauth_token%3Dbar%26oauth_version%3D1.0%26param_1%3Dvalue1%252Cvalue_2%252Cvalue3';
        
        it(' without encoded query parameters', function () {
            var message = {
                    action: 'https://postman.com/path?param_1=value1,value_2,value3',
                    method: 'GET',
                    parameters: {
                        oauth_signature_method: 'HMAC-SHA1',
                        oauth_consumer_key: 'foo',
                        oauth_token: 'bar',
                        oauth_nonce: '3',
                        oauth_timestamp: '123',
                        oauth_version: '1.0'
                    }
                },
                generatedBaseString = getBaseString(message);

            expect(generatedBaseString).to.eql(baseString);
        });

        it('with encoded query parameters', function () {
            var message = {
                    action: 'https://postman.com/path?param_1=value1%2Cvalue_2%2Cvalue3',
                    method: 'GET',
                    parameters: {
                        oauth_signature_method: 'HMAC-SHA1',
                        oauth_consumer_key: 'foo',
                        oauth_token: 'bar',
                        oauth_nonce: '3',
                        oauth_timestamp: '123',
                        oauth_version: '1.0'
                    }
                },
                generatedBaseString = getBaseString(message);

            expect(generatedBaseString).to.eql(baseString);
        });

        it('with query parameters having empty keys', function () {
            var message = {
                    action: 'https://postman.com/path?=a',
                    method: 'GET',
                    parameters: {
                        oauth_signature_method: 'HMAC-SHA1',
                        oauth_consumer_key: 'foo',
                        oauth_token: 'bar',
                        oauth_nonce: '3',
                        oauth_timestamp: '123',
                        oauth_version: '1.0'
                    }
                },
                generatedBaseString = getBaseString(message);

            expect(generatedBaseString).to.eql('GET&https%3A%2F%2Fpostman.com%2Fpath&%3Da%26oauth_consumer_key%3Dfoo%26oauth_nonce%3D3%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D123%26oauth_token%3Dbar%26oauth_version%3D1.0');
        });

        // duplicate query parameters are expected to be sorted by their values
        // Refer: https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.1.3.2
        it('with duplicate query parameters', function () {
            var message = {
                    action: 'https://postman.com/path?a=40&a=20&b=10&b=30&b=20&b=40',
                    method: 'GET',
                    parameters: {
                        oauth_signature_method: 'HMAC-SHA1',
                        oauth_consumer_key: 'foo',
                        oauth_token: 'bar',
                        oauth_nonce: '3',
                        oauth_timestamp: '123',
                        oauth_version: '1.0'
                    }
                },
                generatedBaseString = getBaseString(message);

            expect(generatedBaseString).to.eql('GET&https%3A%2F%2Fpostman.com%2Fpath&a%3D20%26a%3D40%26b%3D10%26b%3D20%26b%3D30%26b%3D40%26oauth_consumer_key%3Dfoo%26oauth_nonce%3D3%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D123%26oauth_token%3Dbar%26oauth_version%3D1.0');
        });
    });
});
