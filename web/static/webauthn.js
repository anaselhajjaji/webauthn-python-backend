// STEP 1
// In this step, the server will create a new credential by calling navigator.credentials.create() on the client side
async function registerCredentials() {

    // CREATE CREDENTIALS
    console.log("STEP 1: Register, create and validate the credentials");
    const publicKeyCredentialCreationOptions = await generateRegistrationOptionsFromBackend();
    
    console.log('-------- publicKeyCredentialCreationOptions', publicKeyCredentialCreationOptions);

    const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
    });

    // PARSING AND VALIDATING THE REGISTRATION DATA
    parseAndValidateCredentialOnBackend(credential);
}

async function generateRegistrationOptionsFromBackend() {
    var randomStringFromServer = 'I am a random string generated from server';

    // Parameters that we'll provide to: navigator.credentials.create()
    return {
        // `challenge`: The challenge is a buffer of cryptographically random bytes generated on the server, and is needed to
        // prevent replay attacks.
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-challenge
        challenge: Uint8Array.from(
            randomStringFromServer, c => c.charCodeAt(0)),

        // `rp`: This stands for “relying party”; it can be considered as describing the organization responsible for
        // registering and authenticating the user.
        // The id must be a subset of the domain currently in the browser.
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-rp
        rp: {
            name: "Anas Localhost",
            id: "localhost", // To make the example work on localhost, otherwise it should be: something.com
        },

        // `user`: This is information about the user currently registering. The authenticator uses the id to associate a
        // credential with the user.
        // It is suggested to not use personally identifying information as the id, as it may be stored in an authenticator.
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-user
        user: {
            id: Uint8Array.from(
                "THE_ID_OF_ANAS_USER", c => c.charCodeAt(0)),
            name: "anas@elhajjaji.com",
            displayName: "Anas EL HAJJAJI",
        },

        // `pubKeyCredParams`: This is an array of objects describing what public key types are acceptable to a server.
        // The alg is a number described in the COSE registry
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-pubkeycredparams
        // Registry Documentation: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        pubKeyCredParams: [
            // -8 [EdDSA - COSE RFC8152 § 2.2](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8148bis-algs-12#section-2.2)
            { type: "public-key", alg: -8 },
            // -7 [Deterministic ECDSA - COSE RFC8152 § 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8148bis-algs-12#section-2.1)
            { type: "public-key", alg: -7 }
        ],

        // `authenticatorSelection`: This optional object helps relying parties make further restrictions on the type of
        // authenticators allowed for registration.
        //
        // If we use `cross-platform` it'll indicate that we want to register a cross-platform authenticator (like a Yubikey)
        // instead of a platform authenticator like Windows Hello or Touch ID. This is, in the context of safetix not what we
        // want as it would allow a authenicator to become portable and not bound to a device.
        // We also require an end user interaction with the authenticator to validate identity.
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-authenticatorselection
        authenticatorSelection: {
            authenticatorAttachment: 'platform',
            requireResidentKey: true,
            userVerification: 'required'
        },

        excludeCredentials: [],

        // `timeout`: The time (in milliseconds) that the user has to respond to a prompt for registration before an error is
        // returned.
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-timeout

        timeout: 60000,

        // `attestation`: The attestation data that is returned from the authenticator has information that could be used to
        // track users.
        // This option allows servers to indicate how important the attestation data is to this registration event.
        // A value of `none` indicates that the server does not care about attestation.
        // A value of `indirect` means that the server will allow for anonymized attestation data.
        // direct means that the server wishes to receive the attestation data from the authenticator.
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#attestation-conveyance
        attestation: "direct"
    };
}

function parseAndValidateCredentialOnBackend(credential) {


    /*  The credential object returned from the create() call is an object containing the public key
        and other attributes used to validate the registration event.

        After the PublicKeyCredential has been obtained, it is sent to the server for validation.
        The WebAuthn specification describes a 19-point procedure to validate the registration data (https://w3c.github.io/webauthn/#registering-a-new-credential);
        Examples:
            - Python (https://github.com/duo-labs/py_webauthn)
            - Go (https://github.com/duo-labs/webauthn).

        PublicKeyCredential {
            // id: The ID for the newly generated credential;
            // it will be used to identify the credential when authenticating the user.
            // The ID is provided here as a base64-encoded string.
            // Spec Documentation: https://w3c.github.io/webauthn/#ref-for-dom-credential-id
            id: 'y0e6uqqj1KJWJW1xFgriHaF1NIeL_dIpvvK_gjL1jKwzpmjuTc6dOY0yv8RxQ4DLni8bLqJ-H9nd1k3R6RrEVp3VnjEp5aZjLs00C1fBgCttKhvHUQ',

            // rawId: The ID again, but in binary form.
            // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredential-rawid
            rawId: ArrayBuffer(59),

            response: AuthenticatorAttestationResponse {
                // clientDataJSON: This represents data passed from the browser to the authenticator in order to associate the new credential with the server and browser.
                // The authenticator provides it as a UTF-8 byte array.
                // Spec Documentation: https://w3c.github.io/webauthn/#dictdef-collectedclientdata
                clientDataJSON: ArrayBuffer(121),

                // attestationObject: This object contains the credential public key, an optional attestation certificate,
                // and other metadata used also to validate the registration event. It is binary data encoded in CBOR.
                // Spec Documentation: https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject
                attestationObject: ArrayBuffer(306),
            },
            type: 'public-key'
        }
    */

    // clientDataJSON
    // The clientDataJSON is parsed by converting the UTF-8 byte array provided by the authenticator into a JSON-parsable string.
    // On this server, this (and the other PublicKeyCredential data) will be verified to ensure that the registration event is valid.
    /*
        {
            // challenge: This is the same challenge that was passed into the create() call.
            // The server must validate that this returned challenge matches the one generated for this registration event.
            challenge: "SSBhbSBhIHJhbmRvbSBzdHJpbmcgZ2VuZXJhdGVkIGZyb20gc2VydmVy",

            // origin: The server must validate that this "origin" string matches up with the origin of the application.
            origin: "http://localhost",

            // type: The server validates that this string is in fact "webauthn.create". If another string is provided,
            // it indicates that the authenticator performed an incorrect operation.
            type: "webauthn.create"
        }
    */

    // decode the clientDataJSON into a utf-8 string
    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(credential.response.clientDataJSON)
    // parse the string as an object
    const clientDataObj = JSON.parse(decodedClientData);
    console.log("-------- clientDataJSON", clientDataObj);

    // attestationObject
    /*
        {
            // authData: The authenticator data is here is a byte array that contains metadata about the registration event,
            // as well as the public key we will use for future authentications.
            // Spec Documentation: https://w3c.github.io/webauthn/#authenticator-data
            authData: Uint8Array(196),

            // fmt: This represents the attestation format. Authenticators can provide attestation data in a number of ways;
            // this indicates how the server should parse and validate the attestation data.
            // Spec Documentation: https://w3c.github.io/webauthn/#attestation-statement-format
            fmt: "packed",

            // attStmt: This is the attestation statement. This object will look different depending on the attestation format indicated.
            // In this case, we are given a signature sig and attestation certificate x5c.
            // Servers use this data to cryptographically verify the credential public key came from the authenticator.
            // Additionally, servers can use the certificate to reject authenticators that are believed to be weak.
            // Spec Documentation: https://w3c.github.io/webauthn/#attestation-statement
            attStmt: {
                sig: Uint8Array(70),
                x5c: Array(1),
            },
        }
    */
    const decodedAttestationObj = CBOR.decode(credential.response.attestationObject);
    console.log('-------- attestationObject', decodedAttestationObj);

    // Parsing
    // The authData is a byte array described in the spec.
    // Parsing it will involve slicing bytes from the array and converting them into usable objects.
    const {authData} = decodedAttestationObj;

    // get the length of the credential ID
    const dataView = new DataView(new ArrayBuffer(2));
    const idLenBytes = authData.slice(53, 55);
    idLenBytes.forEach((value, index) => dataView.setUint8(index, value));

    const credentialIdLength = dataView.getUint16();

    // get the credential ID
    const credentialId = authData.slice(55, 55 + credentialIdLength);

    // get the public key object
    const publicKeyBytes = authData.slice(55 + credentialIdLength);

    // the publicKeyBytes are encoded again as CBOR
    /*
    The publicKeyObject retrieved at the end is an object encoded in a standard called COSE,
    which is a concise way to describe the credential public key and the metadata needed to use it.

    1: The 1 field describes the key type. The value of 2 indicates that the key type is in the Elliptic Curve format.
    3: The 3 field describes the algorithm used to generate authentication signatures. The -7 value indicates this
       authenticator will be using ES256.
    -1: The -1 field describes this key's "curve type". The value 1 indicates the that this key uses the "P-256" curve.
    -2: The -2 field describes the x-coordinate of this public key.
    -3: The -3 field describes the y-coordinate of this public key.
    */
    const publicKeyObject = CBOR.decode(publicKeyBytes.buffer);

    console.log('-------- publicKeyObject', publicKeyObject);

    // END: If the validation process succeeded, the server would then store the publicKeyBytes
    // and credentialId in a database, associated with the user.
    localStorage.setItem('credId', credential.id);

    // Display in screen
    const credentialDiv = document.getElementById('credential');
    credentialDiv.innerHTML =   '<p><b>Credential ID:</b> ' + credential.id + '</p>' +
                                '<p><b>clientDataJSON:</b> ' + decodedClientData + '</p>' +
                                '<p><b>attestationObject (base64):</b>  see developer console (publicKeyObject) </p>';
}

// STEP 2
// After registration has finished, the user can now be authenticated. During authentication an assertion is created,
// which is proof that the user has possession of the private key. This assertion contains a signature created using the
// private key.
// The server uses the public key retrieved during registration to verify this signature.
async function authenticate() {
    console.log("STEP 2: Authentication");
    
    const credentialId = localStorage.getItem('credId');
    console.log('credential id', credentialId);

    const publicKeyCredentialRequestOptions = await generateAuthOptionsFromBackend(credentialId);

    console.log("-------- publicKeyCredentialRequestOptions", publicKeyCredentialRequestOptions);
    const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
    });

    parseAndValidateAssertionOnBackend(assertion);
}

async function generateAuthOptionsFromBackend(credentialId) {

    // During authentication the user proves that they own the private key they registered with.
    // They do so by providing an assertion, which is generated by calling `navigator.credentials.get()` on the client.
    // This will retrieve the credential generated during registration with a signature included.
    var randomStringFromServer = 'I am a random string generated from server';

    return {
        authenticatorSelection: {
            authenticatorAttachment: "platform",
            requireResidentKey: true,
        },

        rpId: "localhost", // To make the example work on localhost, otherwise it should be: something.com

        // `challenge`: Like during registration, this must be cryptographically random bytes generated on the server.
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredentialrequestoptions-challenge
        challenge: Uint8Array.from(
            randomStringFromServer, c => c.charCodeAt(0)),

        // `allowCredentials`: This array tells the browser which credentials the server would like the user to authenticate with.
        // The credentialId retrieved and saved during registration is passed in here. The server can optionally indicate what
        // transports it prefers, like USB, NFC, and Bluetooth.
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredentialrequestoptions-allowcredentials
        allowCredentials: [{
            id: base64DecodeURL(credentialId),
            type: 'public-key',
            // transports: ['usb', 'ble', 'nfc'],
            transports: ['internal'],
        }],

        userVerification: 'required',

        // `timeout`: Like during registration, this optionally indicates the time (in milliseconds) that the user has to
        // respond to a prompt for authentication.
        //
        // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredentialrequestoptions-timeout
        timeout: 60000
    };
}

function parseAndValidateAssertionOnBackend(assertion) {
    console.log("-------- assertion", assertion);

    // The assertion object returned from the get() call is again a PublicKeyCredential object.
    // It is slightly different from the object we received during registration;
    // in particular, it includes a signature member, and does not include the public key.
    /*
        PublicKeyCredential {
            // id: The identifier for the credential that was used to generate the authentication assertion.
            // Spec Documentation: https://w3c.github.io/webauthn/#ref-for-dom-credential-id
            id: 'CmhTyniJPWjCWfdbzNfPHtljT4ePPgEascRYKdzlWdUK6ARoOE…QLrJB_GTDD_42bmTcqMfEqDmyeV5OcKt0pg5TBzF7EiTGA9lQ',

            // rawId: The identifier again, but in binary form.
            // Spec Documentation: https://w3c.github.io/webauthn/#dom-publickeycredential-rawid
            rawId: ArrayBuffer(59),

            response: AuthenticatorAssertionResponse {
                // authenticatorData: The authenticator data is similar to the authData received during registration,
                // with the notable exception that the public key is not included here. It is another item used during authentication
                // as source bytes to generate the assertion signature.
                // Spec Documentation: https://w3c.github.io/webauthn/#authenticator-data
                authenticatorData: ArrayBuffer(191),

                // clientDataJSON: As during registration, the clientDataJSON is a collection of the data passed from the browser to the authenticator.
                // It is one of the items used during authentication as the source bytes to generate the signature.
                // Spec Documentation: https://w3c.github.io/webauthn/#dictdef-collectedclientdata
                clientDataJSON: ArrayBuffer(118),

                // signature: The signature generated by the private key associated with this credential. On the server,
                // the public key will be used to verify that this signature is valid.
                // Spec Documentation: https://w3c.github.io/webauthn/#dom-authenticatorassertionresponse-signature
                signature: ArrayBuffer(70),

                // userHandle: This field is optionally provided by the authenticator, and represents the user.id that was supplied during registration.
                // It can be used to relate this assertion to the user on the server. It is encoded here as a UTF-8 byte array.
                // Spec Documentation: https://w3c.github.io/webauthn/#dom-authenticatorassertionresponse-userhandle
                userHandle: ArrayBuffer(10),
            },
            type: 'public-key'
        }
    */

    // Parsing and Validating the Authentication Data
    /*
        After the assertion has been obtained, it is sent to the server for validation.
        After the authentication data is fully validated, the signature is verified using the public key stored in the database during registration.
        Examples:
            - Python (https://github.com/duo-labs/py_webauthn)
            - Go (https://github.com/duo-labs/webauthn).

        Verification will look different depending on the language and cryptography library used on the server. However, the general procedure remains the same:
            - The server retrieves the public key object associated with the user
            - The server uses the public key to verify the signature, which was generated using the authenticatorData bytes and a SHA-256 hash of the clientDataJSON

        const storedCredential = await getCredentialFromDatabase(
        userHandle, credentialId);

        const signedData = (
            authenticatorDataBytes +
            hashedClientDataJSON);

        const signatureIsValid = storedCredential.publicKey.verify(
            signature, signedData);

        if (signatureIsValid) {
            return "User is authenticated.";
        } else {
            return "Verification failed."
        }

    */
        const authResultDiv = document.getElementById('authResult');
        authResultDiv.innerHTML =   '<p><b>Auth Success!!</b></p>';
}

// Utils
function base64DecodeURL(b64urlstring) {
    return new Uint8Array(atob(b64urlstring.replace(/-/g, '+').replace(/_/g, '/')).split('').map(val => {
        return val.charCodeAt(0);
    }));
}

function base64EncodeURL(byteArray) {
    return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
      return String.fromCharCode(val);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
}
