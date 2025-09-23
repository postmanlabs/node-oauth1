/*
 * Copyright 2008 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var encodeUtf8 = function (str) {
    var te = new TextEncoder();
    return te.encode(str);
}

function arrayBufferToBase64(buffer) {
    if (typeof Buffer !== 'undefined' && Buffer.from) {
        return Buffer.from(buffer).toString('base64');
    }
    var binary = '';
    var bytes = new Uint8Array(buffer);
    for (var i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

async function hmacSignBase64(hashAlg, keyStr, dataStr) {
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
        throw new Error('Web Crypto API is required (globalThis.crypto.subtle)');
    }
    var keyData = encodeUtf8(keyStr == null ? '' : String(keyStr));
    var cryptoKey = await globalThis.crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: { name: hashAlg } },
        false,
        ['sign']
    );
    var sig = await globalThis.crypto.subtle.sign('HMAC', cryptoKey, encodeUtf8(String(dataStr)));
    return arrayBufferToBase64(sig);
}

function pemToDer(pem) {
    var m = /-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----/m.exec(pem);
    if (!m) throw new Error('Invalid PEM');
    var b64 = m[2].replace(/[\r\n\s]/g, '');
    var raw = (typeof Buffer !== 'undefined') ? Buffer.from(b64, 'base64') : Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); });
    var der = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength);
    return { type: m[1], der: der };
}

async function rsaPkcs1SignBase64(hashAlg, privateKey, dataStr) {
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
        throw new Error('Web Crypto API is required (globalThis.crypto.subtle)');
    }
    
    var normalized = { name: 'RSASSA-PKCS1-v1_5', hash: { name: hashAlg } };
    var key;
    if (typeof privateKey === 'string') {
        var info = pemToDer(privateKey);
        var pkcs8Der;
        if (info.type === 'PRIVATE KEY') {
            pkcs8Der = info.der;
        } else if (info.type === 'RSA PRIVATE KEY') {
            pkcs8Der = pkcs1ToPkcs8(info.der);
        } else {
            throw new Error('Provide PKCS#8 PEM (-----BEGIN PRIVATE KEY-----), PKCS#1 PEM (-----BEGIN RSA PRIVATE KEY-----) or JWK');
        }
        key = await globalThis.crypto.subtle.importKey('pkcs8', pkcs8Der, normalized, false, ['sign']);
    } else {
        key = await globalThis.crypto.subtle.importKey('jwk', privateKey, normalized, false, ['sign']);
    }
    var sig = await globalThis.crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encodeUtf8(String(dataStr)));
    return arrayBufferToBase64(sig);
}

// Minimal DER helpers to wrap RSAPrivateKey (PKCS#1) into PKCS#8 PrivateKeyInfo
function derEncodeLength(length) {
    if (length < 128) {
        return new Uint8Array([length]);
    }
    var octets = [];
    var value = length;
    while (value > 0) {
        octets.unshift(value & 0xff);
        value = value >>> 8;
    }
    var result = new Uint8Array(1 + octets.length);
    result[0] = 0x80 | octets.length;
    for (var i = 0; i < octets.length; i++) {
        result[1 + i] = octets[i];
    }
    return result;
}

function concatUint8Arrays() {
    var totalLength = 0;
    for (var i = 0; i < arguments.length; i++) {
        totalLength += arguments[i].length;
    }
    var out = new Uint8Array(totalLength);
    var offset = 0;
    for (var j = 0; j < arguments.length; j++) {
        out.set(arguments[j], offset);
        offset += arguments[j].length;
    }
    return out;
}

function derEncodeTag(tag, content) {
    return concatUint8Arrays(new Uint8Array([tag]), derEncodeLength(content.length), content);
}

function pkcs1ToPkcs8(pkcs1DerBuffer) {
    var pkcs1 = new Uint8Array(pkcs1DerBuffer);
    // version: INTEGER 0
    var version = new Uint8Array([0x02, 0x01, 0x00]);
    // AlgorithmIdentifier: rsaEncryption OID with NULL params
    var oidRsaEncryption = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
    var nullParams = new Uint8Array([0x05, 0x00]);
    var algId = derEncodeTag(0x30, concatUint8Arrays(oidRsaEncryption, nullParams));
    // privateKey: OCTET STRING wrapping RSAPrivateKey DER
    var privateKeyOctet = derEncodeTag(0x04, pkcs1);
    var seqContent = concatUint8Arrays(version, algId, privateKeyOctet);
    var pkcs8 = derEncodeTag(0x30, seqContent);
    return pkcs8.buffer;
}

var OAuth;
if (OAuth == null) OAuth = {};

OAuth.setProperties = function setProperties(into, from) {
    if (into != null && from != null) {
        for (var key in from) {
            into[key] = from[key];
        }
    }
    return into;
}

OAuth.setProperties(OAuth, // utility functions
    {
        percentEncode: function percentEncode(s) {
            if (s == null) {
                return "";
            }
            if (s instanceof Array) {
                var e = "";
                for (var i = 0; i < s.length; ++i) {
                    if (e != "") e += '&';
                    e += OAuth.percentEncode(s[i]);
                }
                return e;
            }
            s = encodeURIComponent(s);
            // Now replace the values which encodeURIComponent doesn't do
            // encodeURIComponent ignores: - _ . ! ~ * ' ( )
            // OAuth dictates the only ones you can ignore are: - _ . ~
            // Source: http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Global_Functions:encodeURIComponent
            s = s.replace(/\!/g, "%21");
            s = s.replace(/\*/g, "%2A");
            s = s.replace(/\'/g, "%27");
            s = s.replace(/\(/g, "%28");
            s = s.replace(/\)/g, "%29");
            return s;
        }
        ,
        decodePercent: function decodePercent(s) {
            if (s != null) {
                // Handle application/x-www-form-urlencoded, which is defined by
                // http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4.1
                s = s.replace(/\+/g, " ");
            }
            return decodeURIComponent(s);
        }
        ,
        /** Convert the given parameters to an Array of name-value pairs. */
        getParameterList: function getParameterList(parameters) {
            if (parameters == null) {
                return [];
            }
            if (typeof parameters != "object") {
                return OAuth.decodeForm(parameters + "");
            }
            if (parameters instanceof Array) {
                return parameters;
            }
            var list = [];
            for (var p in parameters) {
                list.push([p, parameters[p]]);
            }
            return list;
        }
        ,
        /** Convert the given parameters to a map from name to value. */
        getParameterMap: function getParameterMap(parameters) {
            if (parameters == null) {
                return {};
            }
            if (typeof parameters != "object") {
                return OAuth.getParameterMap(OAuth.decodeForm(parameters + ""));
            }
            if (parameters instanceof Array) {
                var map = {};
                for (var p = 0; p < parameters.length; ++p) {
                    var key = parameters[p][0];
                    if (map[key] === undefined) { // first value wins
                        map[key] = parameters[p][1];
                    }
                }
                return map;
            }
            return parameters;
        }
        ,
        getParameter: function getParameter(parameters, name) {
            if (parameters instanceof Array) {
                for (var p = 0; p < parameters.length; ++p) {
                    if (parameters[p][0] == name) {
                        return parameters[p][1]; // first value wins
                    }
                }
            } else {
                return OAuth.getParameterMap(parameters)[name];
            }
            return null;
        }
        ,
        formEncode: function formEncode(parameters) {
            var form = "";
            var list = OAuth.getParameterList(parameters);
            for (var p = 0; p < list.length; ++p) {
                var value = list[p][1];
                if (value == null) value = "";
                if (form != "") form += '&';
                form += OAuth.percentEncode(list[p][0])
                    + '=' + OAuth.percentEncode(value);
            }
            return form;
        }
        ,
        decodeForm: function decodeForm(form) {
            var list = [];
            var nvps = form.split('&');
            for (var n = 0; n < nvps.length; ++n) {
                var nvp = nvps[n];
                if (nvp == "") {
                    continue;
                }
                var equals = nvp.indexOf('=');
                var name;
                var value;
                if (equals < 0) {
                    name = OAuth.decodePercent(nvp);
                    value = null;
                } else {
                    name = OAuth.decodePercent(nvp.substring(0, equals));
                    value = OAuth.decodePercent(nvp.substring(equals + 1));
                }
                list.push([name, value]);
            }
            return list;
        }
        ,
        setParameter: function setParameter(message, name, value) {
            var parameters = message.parameters;
            if (parameters instanceof Array) {
                for (var p = 0; p < parameters.length; ++p) {
                    if (parameters[p][0] == name) {
                        if (value === undefined) {
                            parameters.splice(p, 1);
                        } else {
                            parameters[p][1] = value;
                            value = undefined;
                        }
                    }
                }
                if (value !== undefined) {
                    parameters.push([name, value]);
                }
            } else {
                parameters = OAuth.getParameterMap(parameters);
                parameters[name] = value;
                message.parameters = parameters;
            }
        }
        ,
        setParameters: function setParameters(message, parameters) {
            var list = OAuth.getParameterList(parameters);
            for (var i = 0; i < list.length; ++i) {
                OAuth.setParameter(message, list[i][0], list[i][1]);
            }
        }
        ,
        /** Fill in parameters to help construct a request message.
         This function doesn't fill in every parameter.
         The accessor object should be like:
         {consumerKey:'foo', consumerSecret:'bar', accessorSecret:'nurn', token:'krelm', tokenSecret:'blah'}
         The accessorSecret property is optional.
         */
        completeRequest: async function completeRequest(message, accessor) {
            if (message.method == null) {
                message.method = "GET";
            }
            var map = OAuth.getParameterMap(message.parameters);
            if (map.oauth_consumer_key == null) {
                OAuth.setParameter(message, "oauth_consumer_key", accessor.consumerKey || "");
            }
            if (map.oauth_token == null && accessor.token != null) {
                OAuth.setParameter(message, "oauth_token", accessor.token);
            }
            if (map.oauth_version == null) {
                OAuth.setParameter(message, "oauth_version", "1.0");
            }
            if (map.oauth_timestamp == null) {
                OAuth.setParameter(message, "oauth_timestamp", OAuth.timestamp());
            }
            if (map.oauth_nonce == null) {
                OAuth.setParameter(message, "oauth_nonce", OAuth.nonce(6));
            }
            await OAuth.SignatureMethod.sign(message, accessor);
        }
        ,
        setTimestampAndNonce: function setTimestampAndNonce(message) {
            OAuth.setParameter(message, "oauth_timestamp", OAuth.timestamp());
            OAuth.setParameter(message, "oauth_nonce", OAuth.nonce(6));
        }
        ,
        addToURL: function addToURL(url, parameters) {
            var newURL = url;
            if (parameters != null) {
                var toAdd = OAuth.formEncode(parameters);
                if (toAdd.length > 0) {
                    var q = url.indexOf('?');
                    if (q < 0) newURL += '?';
                    else       newURL += '&';
                    newURL += toAdd;
                }
            }
            return newURL;
        }
        ,
        /** Construct the value of the Authorization header for an HTTP request. */
        getAuthorizationHeader: function getAuthorizationHeader(realm, parameters, disableParamsEncoding) {
            var header = 'OAuth ',
                headerParams = [];

            if (realm && realm.trim()) {
                !disableParamsEncoding && (realm = OAuth.percentEncode(realm));
                headerParams.push(`realm="${realm}"`);
            }

            var list = OAuth.getParameterList(parameters);
            for (var p = 0; p < list.length; ++p) {
                var parameter = list[p];
                var name = parameter[0];
                var value = parameter[1];

                // Skip adding params with no value
                if (!value) { continue; }

                if (typeof value.toString === 'function') {
                    value = value.toString().trim();
                }

                if (!disableParamsEncoding) {
                    name = OAuth.percentEncode(name);
                    value = OAuth.percentEncode(value);
                }

                if (name.indexOf('oauth_') == 0) {
                    headerParams.push(`${name}="${value}"`);
                }
            }

            return header + headerParams.join(',');
        }
        ,
        /** Correct the time using a parameter from the URL from which the last script was loaded. */
        correctTimestampFromSrc: function correctTimestampFromSrc(parameterName) {
            parameterName = parameterName || "oauth_timestamp";
            var scripts = document.getElementsByTagName('script');
            if (scripts == null || !scripts.length) return;
            var src = scripts[scripts.length - 1].src;
            if (!src) return;
            var q = src.indexOf("?");
            if (q < 0) return;
            parameters = OAuth.getParameterMap(OAuth.decodeForm(src.substring(q + 1)));
            var t = parameters[parameterName];
            if (t == null) return;
            OAuth.correctTimestamp(t);
        }
        ,
        /** Generate timestamps starting with the given value. */
        correctTimestamp: function correctTimestamp(timestamp) {
            OAuth.timeCorrectionMsec = (timestamp * 1000) - (new Date()).getTime();
        }
        ,
        /** The difference between the correct time and my clock. */
        timeCorrectionMsec: 0
        ,
        timestamp: function timestamp() {
            var t = (new Date()).getTime() + OAuth.timeCorrectionMsec;
            return Math.floor(t / 1000);
        }
        ,
        nonce: function nonce(length) {
            var chars = OAuth.nonce.CHARS;
            var result = "";
            for (var i = 0; i < length; ++i) {
                var rnum = Math.floor(Math.random() * chars.length);
                result += chars.substring(rnum, rnum + 1);
            }
            return result;
        }
    });

OAuth.nonce.CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";

/** Define a constructor function,
 without causing trouble to anyone who was using it as a namespace.
 That is, if parent[name] already existed and had properties,
 copy those properties into the new constructor.
 */
OAuth.declareClass = function declareClass(parent, name, newConstructor) {
    var previous = parent[name];
    parent[name] = newConstructor;
    if (newConstructor != null && previous != null) {
        for (var key in previous) {
            if (key != "prototype") {
                newConstructor[key] = previous[key];
            }
        }
    }
    return newConstructor;
}

/** An abstract algorithm for signing messages. */
OAuth.declareClass(OAuth, "SignatureMethod", function OAuthSignatureMethod() {
});

OAuth.setProperties(OAuth.SignatureMethod.prototype, // instance members
    {
        /** Add a signature to the message. */
        sign: async function sign(message) {
            var baseString = OAuth.SignatureMethod.getBaseString(message);
            var signature = await this.getSignature(baseString);
            OAuth.setParameter(message, "oauth_signature", signature);
            return signature; // just in case someone's interested
        }
        ,
        /** Set the key string for signing. */
        initialize: function initialize(name, accessor) {
            if (name.startsWith("RSA")) {
                this.key = accessor.privateKey;
                return;
            }

            var consumerSecret;
            if (accessor.accessorSecret != null
                && name.length > 9
                && name.substring(name.length - 9) == "-Accessor") {
                consumerSecret = accessor.accessorSecret;
            } else {
                consumerSecret = accessor.consumerSecret;
            }
            this.key = OAuth.percentEncode(consumerSecret)
                + "&" + OAuth.percentEncode(accessor.tokenSecret);
        }
    });

/* SignatureMethod expects an accessor object to be like this:
 {tokenSecret: "lakjsdflkj...", consumerSecret: "QOUEWRI..", accessorSecret: "xcmvzc..."}
 The accessorSecret property is optional.
 */
// Class members:
OAuth.setProperties(OAuth.SignatureMethod, // class members
    {
        sign: async function sign(message, accessor) {
            var name = OAuth.getParameterMap(message.parameters).oauth_signature_method;
            if (name == null || name == "") {
                name = "HMAC-SHA1";
                OAuth.setParameter(message, "oauth_signature_method", name);
            }
            return OAuth.SignatureMethod.newMethod(name, accessor).sign(message);
        }
        ,
        /** Instantiate a SignatureMethod for the given method name. */
        newMethod: function newMethod(name, accessor) {
            var impl = OAuth.SignatureMethod.REGISTERED[name];
            if (impl != null) {
                var method = new impl();
                method.initialize(name, accessor);
                return method;
            }
            var err = new Error("Unsupported signature method");
            var acceptable = "";
            for (var r in OAuth.SignatureMethod.REGISTERED) {
                if (acceptable != "") acceptable += '&';
                acceptable += OAuth.percentEncode(r);
            }
            err.oauth_acceptable_signature_methods = acceptable;
            throw err;
        }
        ,
        /** A map from signature method name to constructor. */
        REGISTERED: {}
        ,
        /** Subsequently, the given constructor will be used for the named methods.
         The constructor will be called with no parameters.
         The resulting object should usually implement getSignature(baseString).
         You can easily define such a constructor by calling makeSubclass, below.
         */
        registerMethodClass: function registerMethodClass(names, classConstructor) {
            for (var n = 0; n < names.length; ++n) {
                OAuth.SignatureMethod.REGISTERED[names[n]] = classConstructor;
            }
        }
        ,
        /** Create a subclass of OAuth.SignatureMethod, with the given getSignature function. */
        makeSubclass: function makeSubclass(getSignatureFunction) {
            var superClass = OAuth.SignatureMethod;
            var subClass = function () {
                superClass.call(this);
            };
            subClass.prototype = new superClass();
            // Delete instance variables from prototype:
            // delete subclass.prototype... There aren't any.
            subClass.prototype.getSignature = getSignatureFunction;
            subClass.prototype.constructor = subClass;
            return subClass;
        }
        ,
        getBaseString: function getBaseString(message) {
            var URL = message.action;
            var q = URL.indexOf('?');
            var parameters;
            if (q < 0) {
                parameters = message.parameters;
            } else {
                // Combine the URL query string with the other parameters:
                parameters = OAuth.decodeForm(URL.substring(q + 1));
                var toAdd = OAuth.getParameterList(message.parameters);
                for (var a = 0; a < toAdd.length; ++a) {
                    parameters.push(toAdd[a]);
                }
            }
            return OAuth.percentEncode(message.method.toUpperCase())
                + '&' + OAuth.percentEncode(OAuth.SignatureMethod.normalizeUrl(URL))
                + '&' + OAuth.percentEncode(OAuth.SignatureMethod.normalizeParameters(parameters));
        }
        ,
        normalizeUrl: function normalizeUrl(url) {
            var uri = OAuth.SignatureMethod.parseUri(url);
            var scheme = uri.protocol.toLowerCase();
            var authority = uri.authority.toLowerCase();
            var dropPort = (scheme == "http" && uri.port == 80)
                || (scheme == "https" && uri.port == 443);
            if (dropPort) {
                // find the last : in the authority
                var index = authority.lastIndexOf(":");
                if (index >= 0) {
                    authority = authority.substring(0, index);
                }
            }
            var path = uri.path;
            if (!path) {
                path = "/"; // conforms to RFC 2616 section 3.2.2
            }
            // we know that there is no query and no fragment here.
            return scheme + "://" + authority + path;
        }
        ,
        parseUri: function parseUri(str) {
            /* This function was adapted from parseUri 1.2.1
             http://stevenlevithan.com/demo/parseuri/js/assets/parseuri.js
             */
            var o = {
                key: ["source", "protocol", "authority", "userInfo", "user", "password", "host", "port", "relative", "path", "directory", "file", "query", "anchor"],
                parser: { strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@\/]*):?([^:@\/]*))?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/ }
            };
            var m = o.parser.strict.exec(str);
            var uri = {};
            var i = 14;
            while (i--) uri[o.key[i]] = m[i] || "";
            return uri;
        }
        ,
        normalizeParameters: function normalizeParameters(parameters) {
            if (parameters == null) {
                return "";
            }
            var list = OAuth.getParameterList(parameters);
            var sortable = [];
            for (var p = 0; p < list.length; ++p) {
                var nvp = list[p];
                if (nvp[0] != "oauth_signature") {
                    sortable.push([OAuth.percentEncode(nvp[0])
                    + " " // because it comes before any character that can appear in a percentEncoded string.
                    + OAuth.percentEncode(nvp[1])
                        , nvp]);
                }
            }
            sortable.sort(function (a, b) {
                if (a[0] < b[0]) return -1;
                if (a[0] > b[0]) return 1;
                return 0;
            });
            var sorted = [];
            for (var s = 0; s < sortable.length; ++s) {
                sorted.push(sortable[s][1]);
            }
            return OAuth.formEncode(sorted);
        }
    });

OAuth.SignatureMethod.registerMethodClass(["PLAINTEXT", "PLAINTEXT-Accessor"],
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return this.key;
        }
    ));

OAuth.SignatureMethod.registerMethodClass(["HMAC-SHA1", "HMAC-SHA1-Accessor"],
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return hmacSignBase64('SHA-1', this.key, baseString);
        }
    ));

OAuth.SignatureMethod.registerMethodClass(["HMAC-SHA256", "HMAC-SHA256-Accessor"],
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return hmacSignBase64('SHA-256', this.key, baseString);
        }
    ));

OAuth.SignatureMethod.registerMethodClass(["HMAC-SHA512", "HMAC-SHA512-Accessor"],
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return hmacSignBase64('SHA-512', this.key, baseString);
        }
    ));

OAuth.SignatureMethod.registerMethodClass(["RSA-SHA1", "RSA-SHA1-Accessor"],
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return rsaPkcs1SignBase64('SHA-1', this.key, baseString);
        }
    ));

OAuth.SignatureMethod.registerMethodClass(["RSA-SHA256", "RSA-SHA256-Accessor"],
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return rsaPkcs1SignBase64('SHA-256', this.key, baseString);
        }
    ));

OAuth.SignatureMethod.registerMethodClass(["RSA-SHA512", "RSA-SHA512-Accessor"],
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return rsaPkcs1SignBase64('SHA-512', this.key, baseString);
        }
    ));

try {
    OAuth.correctTimestampFromSrc();
} catch (e) {
}


module.exports = OAuth;
