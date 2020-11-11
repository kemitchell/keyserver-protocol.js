const assert = require('assert')

module.exports = function ({
  clientStretch,
  serverStretch,
  serverStretchSaltLength,
  deriveKey,
  authenticate,
  random,
  generateUserID,
  verificationHash,
  authenticationToken: authenticationTokenParameters,
  clientKey: clientKeyParameters,
  serverKey: serverKeyParameters,
  verificationHash: verificationHashParameters,
  responseAuthenticationKey: responseAuthenticationKeyParameters,
  responseEncryptionKey: responseEncryptionKeyParameters,
  requestAuthenticationKey: requestAuthenticationKeyParameters,
  keyRequestToken: keyRequestTokenParameters,
  tokenID: tokenIDParameters
}) {
  // Cryptographic Primitives
  assert(typeof clientStretch === 'function')
  assert(typeof serverStretch === 'function')
  assert(Number.isInteger(serverStretchSaltLength))
  assert(serverStretchSaltLength > 0)
  assert(typeof deriveKey === 'function')
  assert(typeof authenticate === 'function')
  assert(typeof random === 'function')
  assert(typeof generateUserID === 'function')

  // Key Derivation Parameters
  assert(typeof verificationHashParameters === 'object')
  assert(typeof authenticationTokenParameters === 'object')
  assert(typeof clientKeyParameters === 'object')
  assert(typeof serverKeyParameters === 'object')
  assert(typeof responseAuthenticationKeyParameters === 'object')
  assert(typeof responseEncryptionKeyParameters === 'object')
  assert(typeof requestAuthenticationKeyParameters === 'object')
  assert(typeof keyRequestTokenParameters === 'object')
  assert(typeof tokenIDParameters === 'object')

  // API
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

  function clientLogin ({ password, email }) {
    assert(typeof password === 'string')
    assert(password.length > 0)
    const passwordBuffer = Buffer.from(password, 'utf8')

    assert(typeof email === 'string')
    assert(email.length > 0)
    assert(email.indexOf('@') > 1)
    const emailBuffer = Buffer.from(email, 'utf8')

    const clientStretchedPassword = clientStretch({
      password: passwordBuffer,
      salt: emailBuffer
    })
    const authenticationToken = deriveKeyHelper(
      clientStretchedPassword, authenticationTokenParameters
    )

    return {
      authenticationToken,
      clientStretchedPassword
    }
  }

  function serverRegister ({
    clientStretchedPassword,
    authenticationToken
  }) {
    assert(Buffer.isBuffer(clientStretchedPassword))
    assert(clientStretchedPassword.byteLength > 0)

    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    const authenticationSalt = random(serverStretchSaltLength)
    const serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })
    const verificationHash = deriveKeyHelper(
      serverStretchedPassword, verificationHashParameters
    )
    const serverWrappedKey = random(32)
    const userID = generateUserID()

    return {
      authenticationSalt,
      userID,
      serverWrappedKey,
      verificationHash,
      serverStretchedPassword
    }
  }

  function serverLogin ({
    authenticationToken,
    authenticationSalt,
    verificationHash
  }) {
    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    assert(Buffer.isBuffer(authenticationSalt))
    assert(authenticationSalt.byteLength > 0)

    assert(Buffer.isBuffer(verificationHash))
    assert(verificationHash.byteLength > 0)

    const serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })

    const computedVerificationHash = deriveKeyHelper(
      serverStretchedPassword, verificationHashParameters
    )

    return verificationHash.equals(computedVerificationHash)
  }

  function serverRequest ({
    serverStretchedPassword,
    serverWrappedKey,
    keyAccessToken
  }) {
    assert(Buffer.isBuffer(serverStretchedPassword))
    assert(serverStretchedPassword.byteLength > 0)

    assert(Buffer.isBuffer(serverWrappedKey))
    assert(serverWrappedKey.byteLength > 0)

    assert(Buffer.isBuffer(keyAccessToken))
    assert(keyAccessToken.byteLength > 0)

    const parameters = { key: serverStretchedPassword }
    Object.assign(parameters, serverKeyParameters)
    const serverKey = deriveKeyHelper(
      serverStretchedPassword, serverKeyParameters
    )
    const clientWrappedKey = xor(serverKey, serverWrappedKey)

    const tokenID = deriveKeyHelper(
      keyAccessToken, tokenIDParameters
    )
    const requestAuthenticationKey = deriveKeyHelper(
      keyAccessToken, requestAuthenticationKeyParameters
    )
    const keyRequestToken = deriveKeyHelper(
      keyAccessToken, keyRequestTokenParameters
    )

    const responseEncryptionKey = deriveKeyHelper(
      keyRequestToken, responseEncryptionKeyParameters
    )
    const responseAuthenticationKey = deriveKeyHelper(
      keyRequestToken, responseAuthenticationKeyParameters
    )

    const ciphertext = xor(clientWrappedKey, responseEncryptionKey)
    const mac = authenticate({
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

  function clientRequest ({
    ciphertext,
    mac,
    clientStretchedPassword,
    keyAccessToken
  }) {
    assert(Buffer.isBuffer(ciphertext))
    assert(Buffer.isBuffer(mac))
    assert(Buffer.isBuffer(clientStretchedPassword))
    assert(Buffer.isBuffer(keyAccessToken))

    const keyRequestToken = deriveKeyHelper(
      keyAccessToken, keyRequestTokenParameters
    )

    const responseAuthenticationKey = deriveKeyHelper(
      keyRequestToken, responseAuthenticationKeyParameters
    )
    const responseEncryptionKey = deriveKeyHelper(
      keyRequestToken, responseEncryptionKeyParameters
    )

    const computedMAC = authenticate({
      key: responseAuthenticationKey,
      input: ciphertext
    })

    if (!mac.equals(computedMAC)) return false

    const clientWrappedKey = xor(ciphertext, responseEncryptionKey)

    const clientKey = deriveKeyHelper(
      clientStretchedPassword, clientKeyParameters
    )

    const encryptionKey = xor(clientWrappedKey, clientKey)

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
  const returned = Buffer.alloc(a.length)
  for (let offset = 0; offset < a.length; offset++) {
    returned[offset] = a[offset] ^ b[offset]
  }
  return returned
}
