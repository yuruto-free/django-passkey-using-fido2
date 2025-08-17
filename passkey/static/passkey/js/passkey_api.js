'use strict';

const PasskeyAPI = {};

(function () {
  const base64url = (() => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    // Create lookup table
    const lookupTable = new Uint8Array(256);
    for (let idx = chars.length - 1; idx >= 0; idx--) {
      lookupTable[chars.charCodeAt(idx)] = idx;
    }

    const encodeFromBuffer = (buf) => {
      const bytes = new Uint8Array(buf);
      const len = bytes.length;
      let base64string = '';

      for (let idx = 0; idx < len; idx += 3) {
        base64string += chars[bytes[idx] >> 2];
        base64string += chars[((bytes[idx] & 3) << 4) | (bytes[idx + 1] >> 4)];
        base64string += chars[((bytes[idx + 1] & 15) << 2) | (bytes[idx + 2] >> 6)];
        base64string += chars[bytes[idx + 2] & 63];
      }

      if ((len % 3) === 2) {
        base64string = base64string.substring(0, base64string.length - 1);
      }
      else if (len % 3 === 1) {
        base64string = base64string.substring(0, base64string.length - 2);
      }

      return base64string;
    };

    const decodeFromString = (base64string) => {
      const len = base64string.length;
      const bytes = new Uint8Array(len * 0.75);
      let pos = 0;

      for (let idx = 0; idx < len; idx += 4) {
        const encoded1 = lookupTable[base64string.charCodeAt(idx)];
        const encoded2 = lookupTable[base64string.charCodeAt(idx + 1)];
        const encoded3 = lookupTable[base64string.charCodeAt(idx + 2)];
        const encoded4 = lookupTable[base64string.charCodeAt(idx + 3)];
        bytes[pos++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[pos++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[pos++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
      }

      return bytes.buffer;
    };

    const methods = {
      encode: encodeFromBuffer,
      decode: decodeFromString,
    };

    return methods;
  })();

  const publicKeyCredentialToJSON = (cred) => {
    const _convertClientExtension = (extension) => {
      const obj = {};

      for (const key of Object.keys(extension)) {
        obj[key] = base64url.encode(extension[key]);
      }

      return obj;
    };
    const _convertResponse = (response) => {
      const _convertor = (arr) => Object.fromEntries(arr.map((val, idx) => [idx, val]));

      if (response instanceof AuthenticatorAttestationResponse) {
        const obj = {
          attestationObject: base64url.encode(response.attestationObject),
          authenticatorData: base64url.encode(response.getAuthenticatorData()),
          clientDataJSON: base64url.encode(response.clientDataJSON),
          publicKey: base64url.encode(response.getPublicKey()),
          publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
          transports: _convertor(response.getTransports()),
        }

        return obj;
      }
      else if (response instanceof AuthenticatorAssertionResponse) {
        const obj = {
          authenticatorData: base64url.encode(response.authenticatorData),
          clientDataJSON: base64url.encode(response.clientDataJSON),
          signature: base64url.encode(response.signature),
          userHandle: base64url.encode(response.userHandle),
        };

        return obj;
      }
      else {
        return undefined;
      }
    };

    // main process
    if ('toJSON' in cred) {
      return cred.toJSON();
    }
    else {
      const obj = {
        authenticatorAttachment: cred.authenticatorAttachment || undefined,
        clientExtensionResults: _convertClientExtension(cred.getClientExtensionResults()),
        id: cred.id,
        rawId: base64url.encode(cred.rawId),
        response: _convertResponse(cred.response),
        type: cred.type,
      };
      const ret = {};
      // Delete `undefined` element
      for (const key of Object.keys(obj)) {
        if (obj[key]) {
          ret[key] = obj[key];
        }
      }

      return ret;
    }
  };

  const makeCredOptions = (data) => {
    data.publicKey.challenge = base64url.decode(data.publicKey.challenge);
    data.publicKey.user.id = base64url.decode(data.publicKey.user.id);

    for (const excludeCred of data.publicKey.excludeCredentials) {
      excludeCred.id = base64url.decode(excludeCred.id);
    }

    return data;
  };

  const getAssertOptions = (data) => {
    data.publicKey.challenge = base64url.decode(data.publicKey.challenge);

    for (const allowCred of data.publicKey.allowCredentials) {
      allowCred.id = base64url.decode(allowCred.id);
    }

    return data;
  };

  // ===========
  // Define APIs
  // ===========
  PasskeyAPI.Init = () => {
    window.conditionalUI = false;
    window.conditionUIAbortController = new AbortController();
    window.conditionUIAbortSignal = window.conditionUIAbortController.signal;
  };

  PasskeyAPI.CheckConditionalUI = (callback) => {
    if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable) {
      PublicKeyCredential.isConditionalMediationAvailable().then((isAvailable) => {
        window.conditionalUI = isAvailable;
        callback(isAvailable, 'Cannot use conditional UI');
      }).catch((err) => {
        callback(false, err);
      });
    }
  };

  PasskeyAPI.CheckPasskeys = (callback) => {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then((isAvailable) => {
      callback(isAvailable, 'Cannot use passkey on your device.');
    }).catch((err) => {
      callback(false, err);
    });
  };

  PasskeyAPI.RegisterPasskey = (registerURL, keyName, csrftoken, callback) => {
    fetch(registerURL, { method: 'GET' }).then((response) => {
      if (!response.ok) {
        throw new Error('Cannot get registration data.');
      }

      return response.json();
    }).then((data) => {
      const options = makeCredOptions(data);

      return navigator.credentials.create(options);
    }).then((credential) => {
      const headers = {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken,
      };
      const jsonData = publicKeyCredentialToJSON(credential);
      jsonData['key_name'] = keyName;

      return fetch(registerURL, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(jsonData),
      });
    }).then((response) => {
      return response.json().then((data) => {
        callback(response.ok, data.message);
      });
    }).catch((err) => {
      callback(false, err);
    });
  };

  PasskeyAPI.Authentication = (authURL, callback) => {
    fetch(authURL, { method: 'GET' }).then((response) => {
      if (!response.ok) {
        throw new Error('No credential available to authenticate.');
      }

      return response.json();
    }).then((data) => {
      const options = getAssertOptions(data);

      if (window.conditionalUI) {
        options.mediation = 'conditional';
        options.signal = window.conditionUIAbortSignal;
      }
      else {
        window.conditionUIAbortController.abort('Abort manually');
      }

      return navigator.credentials.get(options);
    }).then((assertion) => {
      const jsonData = publickeyCredentialToJson(assertion);
      callback(true, jsonData);
    }).catch((err) => {
      callback(false, err);
    });
  };

  Object.freeze(PasskeyAPI);
})();