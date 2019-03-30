var assert = require('assert')

module.exports = function (primitives) {
  assert(typeof primitives === 'object')

  // Encryption Key

  var encryptionKeyLength = primitives.encryptionKeyLength
  assert(Number.isInteger(encryptionKeyLength))
  assert(encryptionKeyLength > 0)

  // Cryptographic Primitives

  var clientStretch = primitives.clientStretch
  assert(typeof clientStretch === 'function')

  var serverStretch = primitives.serverStretch
  assert(typeof serverStretch === 'function')

  var serverStretchSaltLength = primitives.serverStretchSaltLength
  assert(Number.isInteger(serverStretchSaltLength))
  assert(serverStretchSaltLength > 0)

  var hkdf = primitives.hkdf
  assert(typeof hkdf === 'function')

  var hmac = primitives.hmac
  assert(typeof hmac === 'function')

  var random = primitives.random
  assert(typeof random === 'function')

  var generateUserID = primitives.generateUserID
  assert(typeof generateUserID === 'function')

  var generateToken = primitives.generateToken
  assert(typeof generateToken === 'function')

  // HKDF Parameters

  var verificationHashSubkey = primitives.verificationHashSubkey
  assert(Number.isInteger(verificationHashSubkey))
  var verificationHashContext = primitives.verificationHashContext
  assert(Buffer.isBuffer(verificationHashContext))

  var authenticationTokenSubkey = primitives.authenticationTokenSubkey
  assert(Number.isInteger(authenticationTokenSubkey))
  var authenticationTokenContext = primitives.authenticationTokenContext
  assert(Buffer.isBuffer(authenticationTokenContext))

  var clientKeySubkey = primitives.clientKeySubkey
  assert(Number.isInteger(clientKeySubkey))
  var clientKeyContext = primitives.clientKeyContext
  assert(Buffer.isBuffer(clientKeyContext))

  var serverKeySubkey = primitives.serverKeySubkey
  assert(Number.isInteger(serverKeySubkey))
  var serverKeyContext = primitives.serverKeyContext
  assert(Buffer.isBuffer(serverKeyContext))

  var fromKeyAccessTokenSubkey = primitives.fromKeyAccessTokenSubkey
  assert(Number.isInteger(fromKeyAccessTokenSubkey))
  var fromKeyAccessTokenContext = primitives.fromKeyAccessTokenContext
  assert(Buffer.isBuffer(fromKeyAccessTokenContext))

  var fromKeyRequestTokenSubkey = primitives.fromKeyRequestTokenSubkey
  assert(Number.isInteger(fromKeyRequestTokenSubkey))
  var fromKeyRequestTokenContext = primitives.fromKeyRequestTokenContext
  assert(Buffer.isBuffer(fromKeyRequestTokenContext))

  var tokenIDSubkey = primitives.tokenIDSubkey
  assert(Number.isInteger(tokenIDSubkey))
  var tokenIDContext = primitives.tokenIDContext
  assert(Buffer.isBuffer(tokenIDContext))

  return {
    client: {
      login: clientLogin,
      request: clientRequest
    },
    server: {
      register: serverRegister,
      login: serverLogin,
      request: serverRequest
    }
  }

  function clientLogin (input) {
    assert(typeof input === 'object')

    var password = input.password
    assert(typeof password === 'string')
    assert(password.length > 0)
    var passwordBuffer = Buffer.from(password)

    var email = input.email
    assert(typeof email === 'string')
    assert(email.length > 0)
    assert(email.indexOf('@') > 1)
    var emailBuffer = Buffer.from(email)

    var clientStretchedPassword = clientStretch({
      password: passwordBuffer, salt: emailBuffer
    })
    var authenticationToken = hkdf({
      key: clientStretchedPassword,
      subkey: authenticationTokenSubkey,
      context: authenticationTokenContext
    })

    return {
      authenticationToken,
      clientStretchedPassword
    }
  }

  function serverRegister (input) {
    assert(typeof input === 'object')

    var clientStretchedPassword = input.clientStretchedPassword
    assert(Buffer.isBuffer(clientStretchedPassword))
    assert(clientStretchedPassword.byteLength > 0)

    var authenticationToken = input.authenticationToken
    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    var authenticationSalt = random(serverStretchSaltLength)
    var serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })
    var verificationHash = hkdf({
      key: serverStretchedPassword,
      subkey: verificationHashSubkey,
      context: verificationHashContext
    })
    var serverWrappedKey = random(encryptionKeyLength)
    var userID = generateUserID()

    return {
      authenticationSalt,
      userID,
      serverWrappedKey,
      verificationHash,
      serverStretchedPassword,
      sessionToken: generateToken(),
      keyAccessToken: generateToken()
    }
  }

  function serverLogin (input) {
    assert(typeof input === 'object')

    var authenticationToken = input.authenticationToken
    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    var authenticationSalt = input.authenticationSalt
    assert(Buffer.isBuffer(authenticationSalt))
    assert(authenticationSalt.byteLength > 0)

    var serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })

    var storedVerificationHash = input.verificationHash

    var computedVerificationHash = hkdf({
      key: serverStretchedPassword,
      subkey: verificationHashContext,
      context: verificationHashContext
    })

    if (!storedVerificationHash.equals(computedVerificationHash)) {
      return false
    }

    return {
      keyAccessToken: generateToken(),
      sessionToken: generateToken()
    }
  }

  function serverRequest (input) {
    assert(typeof input === 'object')

    var serverStretchedPassword = input.serverStretchedPassword
    assert(Buffer.isBuffer(serverStretchedPassword))
    assert(serverStretchedPassword.byteLength > 0)

    var serverWrappedKey = input.serverWrappedKey
    assert(Buffer.isBuffer(serverWrappedKey))
    assert(serverWrappedKey.byteLength > 0)

    var keyAccessToken = input.keyAccessToken
    assert(Buffer.isBuffer(keyAccessToken))
    assert(keyAccessToken.byteLength > 0)

    var serverKey = hkdf({
      key: serverStretchedPassword,
      subkey: serverKeySubkey,
      context: serverKeyContext
    })
    var clientWrappedKey = xor(serverKey, serverWrappedKey)

    var fromKeyAccessToken = deriveFromKeyAccessToken(keyAccessToken)
    var tokenID = fromKeyAccessToken.tokenID
    var requestAuthenticationKey = fromKeyAccessToken.requestAuthenticationKey
    var keyRequestToken = fromKeyAccessToken.keyRequestToken

    var fromKeyRequestToken = deriveFromKeyRequestToken(keyRequestToken)
    var responseAuthenticationKey = fromKeyRequestToken.responseAuthenticationKey
    var responseEncryptionKey = fromKeyRequestToken.responseEncryptionKey

    var ciphertext = xor(clientWrappedKey, responseEncryptionKey)
    var mac = hmac({
      key: responseAuthenticationKey,
      input: ciphertext
    })

    return {
      ciphertext,
      mac,
      requestAuthenticationKey,
      tokenID
    }
  }

  function clientRequest (input) {
    assert(typeof input === 'object')

    var ciphertext = input.ciphertext
    assert(Buffer.isBuffer(ciphertext))

    var providedMAC = input.mac
    assert(Buffer.isBuffer(providedMAC))

    var clientStretchedPassword = input.clientStretchedPassword
    assert(Buffer.isBuffer(clientStretchedPassword))

    var keyAccessToken = input.keyAccessToken
    assert(Buffer.isBuffer(keyAccessToken))

    var fromKeyAccessToken = deriveFromKeyAccessToken(keyAccessToken)
    // var tokenID = fromKeyAccessToken.tokenID
    // var requestAuthenticationKey = fromKeyAccessToken.requestAuthenticationKey
    var keyRequestToken = fromKeyAccessToken.keyRequestToken

    var fromKeyRequestToken = deriveFromKeyRequestToken(keyRequestToken)
    var responseAuthenticationKey = fromKeyRequestToken.responseAuthenticationKey
    var responseEncryptionKey = fromKeyRequestToken.responseEncryptionKey

    var computedMAC = hmac({
      key: responseAuthenticationKey,
      input: ciphertext
    })

    if (!providedMAC.equals(computedMAC)) return false

    var clientWrappedKey = xor(ciphertext, responseEncryptionKey)

    var clientKey = hkdf({
      key: clientStretchedPassword,
      subkey: clientKeySubkey,
      context: clientKeyContext
    })

    var encryptionKey = xor(clientWrappedKey, clientKey)

    return {
      encryptionKey
    }
  }

  function deriveFromKeyAccessToken (keyAccessToken) {
    // TODO: Verify this is best for > crypto_kdf_BYTES_MAX.
    var tokenID = hkdf({
      key: keyAccessToken,
      subkey: tokenIDSubkey,
      context: tokenIDContext,
      length: 32
    })
    var buffer = hkdf({
      key: keyAccessToken,
      subkey: fromKeyAccessTokenSubkey,
      context: fromKeyAccessTokenContext,
      length: 2 * 32
    })

    return {
      keyRequestToken: buffer.slice(32, 64),
      requestAuthenticationKey: buffer.slice(0, 32),
      tokenID
    }
  }

  function deriveFromKeyRequestToken (keyRequestToken) {
    var buffer = hkdf({
      key: keyRequestToken,
      subkey: fromKeyRequestTokenSubkey,
      context: fromKeyRequestTokenContext,
      length: 2 * 32
    })

    return {
      responseAuthenticationKey: buffer.slice(0, 32),
      responseEncryptionKey: buffer.slice(32, 65)
    }
  }
}

function xor (a, b) {
  var returned = Buffer.alloc(a.length)
  for (var offset = 0; offset < a.length; offset++) {
    returned[offset] = a[offset] ^ b[offset]
  }
  return returned
}
