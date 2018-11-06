const crypto    = require('crypto');
const base64url = require('base64url');
const cbor      = require('cbor');

/**
 * U2F Presence constant
 */
const U2F_USER_PRESENTED = 0x01;
/**
 * U2F Verification required constant
 */
const U2F_USER_VERIFICATION_REQUIRED = 0x04;

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
const verifySignature = (signature, data, publicKey) => {
    return crypto.createVerify('SHA256')
        .update(data)
        .verify(publicKey, signature);
}


/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
const randomBase64URLBuffer = (len) => {
    len = len || 32;

    let buff = crypto.randomBytes(len);

    return base64url(buff);
}

/**
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
const generateServerMakeCredRequest = (username, displayName, id) => {
    return {
        challenge: randomBase64URLBuffer(32),

        rp: {
            name: "NGTI Webauthn RP"
        },

        user: {
            id: id,
            name: username,
            displayName: displayName
        },

        attestation: 'direct',

        pubKeyCredParams: [
            {
                type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
            }
        ]
    }
}

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
const generateServerGetAssertion = (authenticators) => {
    let allowCredentials = [];
    for(let authenticator of authenticators) {
        allowCredentials.push({
              type: 'public-key',
              id: authenticator.credID,
              transports: ['internal', 'usb', 'nfc', 'ble']
        })
    }
    return {
        challenge: randomBase64URLBuffer(32),
        allowCredentials: allowCredentials
    }
}


/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
const hash = (data) => {
    return crypto.createHash('SHA256').update(data).digest();
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
const COSEECDHAtoPKCS = (COSEPublicKey) => {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
    let tag = Buffer.from([0x04]);
    let x   = coseStruct.get(-2);
    let y   = coseStruct.get(-3);

    return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
const ASN1toPEM = (pkBuffer) => {
    if (!Buffer.isBuffer(pkBuffer))
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

    let type;
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */
        
        pkBuffer = Buffer.concat([
            new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            pkBuffer
        ]);

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = pkBuffer.toString('base64');

    let PEMKey = '';
    for(let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMKey += b64cert.substr(start, 64) + '\n';
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;
    
    return PEMKey
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
const parseMakeCredAuthData = (buffer) => {
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flags         = flagsBuf[0];
    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);
    let aaguid        = buffer.slice(0, 16);          buffer = buffer.slice(16);
    let credIDLenBuf  = buffer.slice(0, 2);           buffer = buffer.slice(2);
    let credIDLen     = credIDLenBuf.readUInt16BE(0);
    let credID        = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
    let COSEPublicKey = buffer;

    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}
}

const verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
    const attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    const ctapMakeCredResp  = cbor.decodeAllSync(attestationBuffer)[0];
    const authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);
    const clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));

    if(!(authrDataStruct.flags & U2F_USER_PRESENTED))
        throw new Error('User was NOT presented durring authentication!');
        
    const publicKey       = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);

    console.log('-XXX->verifyAuthenticatorAttestationResponse, attestation=', attestationBuffer);
    console.log('-XXX->verifyAuthenticatorAttestationResponse, authData=', authrDataStruct, ', pubKey=', publicKey);
    let response = {'verified': false};
    if(ctapMakeCredResp.fmt === 'fido-u2f') {
        const reservedByte    = Buffer.from([0x00]);
        const signatureBase   = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

        const PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
        const signature      = ctapMakeCredResp.attStmt.sig;

        response.verified = verifySignature(signature, signatureBase, PEMCertificate)

        if(response.verified) {
            response.authrInfo = {
                fmt: 'fido-u2f',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    } else if (ctapMakeCredResp.fmt === 'packed') {
        //1. Let authenticatorData denote the authenticator data for the attestation, and let 
        //   clientDataHash denote the hash of the serialized client data.
        //2. If Basic or AttCA attestation is in use, the authenticator produces the sig by 
        //   concatenating authenticatorData and clientDataHash, and signing the result using an 
        //   attestation private key selected through an authenticator-specific mechanism. It sets
        //   x5c to the certificate chain of the attestation public key and alg to the algorithm 
        //   of the attestation private key.
        //3. If ECDAA is in use, the authenticator produces sig by concatenating authenticatorData
        //   and clientDataHash, and signing the result using ECDAA-Sign (see section 3.5 of [FIDOEcdaaAlgorithm])
        //   after selecting an ECDAA-Issuer public key related to the ECDAA signature private key
        //   through an authenticator-specific mechanism (see [FIDOEcdaaAlgorithm]). It sets alg to
        //   the algorithm of the selected ECDAA-Issuer public key and ecdaaKeyId to the identifier
        //   of the ECDAA-Issuer public key (see above).
        //4. If self attestation is in use, the authenticator produces sig by concatenating authenticatorData
        //   and clientDataHash, and signing the result using the credential private key. It sets alg to
        //   the algorithm of the credential private key and omits the other fields.
        console.log('-XXX->attestation statement fmt PACKED! attStmt=', ctapMakeCredResp.attStmt);
        const x5Certficates = ctapMakeCredResp.attStmt.x5c;
        const ecdaaKeyId = ctapMakeCredResp.attStmt.ecdaaKeyId;
        if (x5Certficates && x5Certficates.length > 0) {
            // Verify X5c Signature
            console.log('-XXX->Verify X5c Signature, TO BE IMPLEMENTED!');
        } else if (ecdaaKeyId) {
            // Verify ECDAA Signature
            console.log('-XXX->Verify ECDAA Signature, TO BE IMPLEMENTED!');
        } else {
            // Self Attestation
            //1. Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            //2. Verify that sig is a valid signature over the concatenation of authenticatorData and
            //   clientDataHash using the credential public key with alg.
            //If successful, return attestation type Self and empty attestation trust path.
            const sigAlgId = ctapMakeCredResp.attStmt.alg;
            console.log('-XXX->encoded with sigAlgId=', sigAlgId);
            if (sigAlgId === -7) {
                console.log('ES256 algorithm');
            }
            const alg = cbor.decodeAllSync(authrDataStruct.COSEPublicKey)[3];
            console.log('-XXX->decoded algId=', alg);
            const signature = ctapMakeCredResp.attStmt.sig;
            const signatureBase = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);
            response.verified = verifySignature(signature, signatureBase, ASN1toPEM(publicKey));
            if(response.verified) {
                response.authrInfo = {
                    fmt: 'packed',
                    publicKey: base64url.encode(publicKey),
                    counter: authrDataStruct.counter,
                    credID: base64url.encode(authrDataStruct.credID)
                }
            }
        }
    } else {
        console.log('-XXX->attestation statement fmt=', ctapMakeCredResp.fmt, ' NOT YET SUPPORTED!');
    }

    return response
}

/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
const findAuthr = (credID, authenticators) => {
    for(let authr of authenticators) {
        if(authr.credID === credID)
            return authr
    }

    throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
const parseGetAssertAuthData = (buffer) => {
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flags         = flagsBuf[0];
    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);

    return {rpIdHash, flagsBuf, flags, counter, counterBuf}
}

const verifyAuthenticatorAssertionResponse = (webAuthnResponse, authenticators) => {
    console.log('-XXX->verifyAuthenticatorAssertionResponse');
    const authr = findAuthr(webAuthnResponse.id, authenticators);
    const authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData);

    let response = {'verified': false};
    if(authenticatorData) {
        let authrDataStruct  = parseGetAssertAuthData(authenticatorData);
        console.log('-XXX->authData, ', authrDataStruct);
        if(!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        const clientDataHash   = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        const signatureBase    = Buffer.concat([authenticatorData, clientDataHash]);

        const publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
        const signature = base64url.toBuffer(webAuthnResponse.response.signature);

        console.log('-XXX->verifySignature, publicKey=', publicKey);
        response.verified = verifySignature(signature, signatureBase, publicKey);
        if(response.verified) {
            if(response.counter <= authr.counter)
                throw new Error('Authenticator counter did not increase!');

            authr.counter = authrDataStruct.counter
        }
    }

    return response
}

module.exports = {
    randomBase64URLBuffer,
    generateServerMakeCredRequest,
    generateServerGetAssertion,
    verifyAuthenticatorAttestationResponse,
    verifyAuthenticatorAssertionResponse
}