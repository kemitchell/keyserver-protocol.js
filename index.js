var assert = require('assert')

module.exports = function (configuration) {
  assert(typeof configuration === 'object')

  // Cryptographic Primitives

  var clientStretch = configuration.clientStretch
  assert(typeof clientStretch === 'function')

  var serverStretch = configuration.serverStretch
  assert(typeof serverStretch === 'function')

  var serverStretchSaltLength = configuration.serverStretchSaltLength
  assert(Number.isInteger(serverStretchSaltLength))
  assert(serverStretchSaltLength > 0)

  var deriveKey = configuration.deriveKey
  assert(typeof deriveKey === 'function')

  var authenticate = configuration.authenticate
  assert(typeof authenticate === 'function')

  var random = configuration.random
  assert(typeof random === 'function')

  var generateUserID = configuration.generateUserID
  assert(typeof generateUserID === 'function')

  // Key Derivation Parameters

  var verificationHashParameters = configuration.verificationHash
  assert(typeof verificationHashParameters === 'object')

  var authenticationTokenParameters = configuration.authenticationToken
  assert(typeof authenticationTokenParameters === 'object')

  var clientKeyParameters = configuration.clientKey
  assert(typeof clientKeyParameters === 'object')

  var serverKeyParameters = configuration.serverKey
  assert(typeof serverKeyParameters === 'object')

  var responseAuthenticationKeyParameters = configuration.responseAuthenticationKey
  assert(typeof responseAuthenticationKeyParameters === 'object')

  var responseEncryptionKeyParameters = configuration.responseEncryptionKey
  assert(typeof responseEncryptionKeyParameters === 'object')

  var requestAuthenticationKeyParameters = configuration.requestAuthenticationKey
  assert(typeof requestAuthenticationKeyParameters === 'object')

  var keyRequestTokenParameters = configuration.keyRequestToken
  assert(typeof keyRequestTokenParameters === 'object')

  var tokenIDParameters = configuration.tokenID
  assert(typeof tokenIDParameters === 'object')

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
    var passwordBuffer = Buffer.from(password, 'utf8')

    var email = input.email
    assert(typeof email === 'string')
    assert(email.length > 0)
    assert(email.indexOf('@') > 1)
    var emailBuffer = Buffer.from(email, 'utf8')

    var clientStretchedPassword = clientStretch({
      password: passwordBuffer,
      salt: emailBuffer
    })
    var authenticationToken = deriveKeyHelper(
      clientStretchedPassword, authenticationTokenParameters
    )

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
    var verificationHash = deriveKeyHelper(
      serverStretchedPassword, verificationHashParameters
    )
    var serverWrappedKey = random(32)
    var userID = generateUserID()

    return {
      authenticationSalt,
      userID,
      serverWrappedKey,
      verificationHash,
      serverStretchedPassword
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

    var storedVerificationHash = input.verificationHash
    assert(Buffer.isBuffer(storedVerificationHash))
    assert(storedVerificationHash.byteLength > 0)

    var serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })

    var computedVerificationHash = deriveKeyHelper(
      serverStretchedPassword, verificationHashParameters
    )

    if (!storedVerificationHash.equals(computedVerificationHash)) {
      return false
    }

    return true
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

    var parameters = { key: serverStretchedPassword }
    Object.assign(parameters, serverKeyParameters)
    var serverKey = deriveKeyHelper(
      serverStretchedPassword, serverKeyParameters
    )
    var clientWrappedKey = xor(serverKey, serverWrappedKey)

    var tokenID = deriveKeyHelper(
      keyAccessToken, tokenIDParameters
    )
    var requestAuthenticationKey = deriveKeyHelper(
      keyAccessToken, requestAuthenticationKeyParameters
    )
    var keyRequestToken = deriveKeyHelper(
      keyAccessToken, keyRequestTokenParameters
    )

    var responseEncryptionKey = deriveKeyHelper(
      keyRequestToken, responseEncryptionKeyParameters
    )
    var responseAuthenticationKey = deriveKeyHelper(
      keyRequestToken, responseAuthenticationKeyParameters
    )

    var ciphertext = xor(clientWrappedKey, responseEncryptionKey)
    var mac = authenticate({
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

    var keyRequestToken = deriveKeyHelper(
      keyAccessToken, keyRequestTokenParameters
    )

    var responseAuthenticationKey = deriveKeyHelper(
      keyRequestToken, responseAuthenticationKeyParameters
    )
    var responseEncryptionKey = deriveKeyHelper(
      keyRequestToken, responseEncryptionKeyParameters
    )

    var computedMAC = authenticate({
      key: responseAuthenticationKey,
      input: ciphertext
    })

    if (!providedMAC.equals(computedMAC)) return false

    var clientWrappedKey = xor(ciphertext, responseEncryptionKey)

    var clientKey = deriveKeyHelper(
      clientStretchedPassword, clientKeyParameters
    )

    var encryptionKey = xor(clientWrappedKey, clientKey)

    return { encryptionKey }
  }

  function deriveKeyHelper (key, parameters) {
    assert(Buffer.isBuffer(key))
    assert(typeof parameters === 'object')
    return deriveKey(Object.assign({ key }, parameters))
  }
}

function xor (a, b) {
  assert(a.length === b.length)
  var returned = Buffer.alloc(a.length)
  for (var offset = 0; offset < a.length; offset++) {
    returned[offset] = a[offset] ^ b[offset]
  }
  return returned
}
