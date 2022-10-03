# Imports
import os
import base64
from pydoc import cli
from flask import Flask, json, request, jsonify, render_template
from flask_cors import CORS, cross_origin
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json
)
from webauthn.helpers import (
    base64url_to_bytes,
    parse_client_data_json,
    parse_attestation_object,
    parse_authenticator_data
)
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationFormat,
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    UserVerificationRequirement,
    AuthenticationCredential,
)
from webauthn.registration.formats.android_safetynet import SafetyNetJWSPayload
import pickledb

db = pickledb.load('webauthn.db', False)

api = Flask(__name__)
cors = CORS(api)
api.config['CORS_HEADERS'] = 'Content-Type'

@api.route("/")
def index_page():
    return render_template('index.html')

########################################################################
#
#  will be called by js: generateAuthOptionsFromBackend()
#
########################################################################
@api.route('/generate_registration_opts', methods=['GET'])
# to enable CORS for the example
@cross_origin()
def generate_registration_opts():
    """To generate webauthn registration options"""

    user_agent=request.headers.get('User-Agent')

    # retrieves user id from argument
    args=request.args
    user_id=args.get("userId")
    print("------------------ generate_registration_opts for user id")
    print(user_id)

    registration_options = generate_registration_options(
        # RP Options
        rp_id=get_expected_rpid(user_agent),
        rp_name="RP On webauthn-python-backend.herokuapp.com",
        
        # User registration options: should be sent in the request
        user_id=user_id,
        user_name="Name Of " + user_id,
        user_display_name="Display Name Of " + user_id,

        # Supported Public keys
        supported_pub_key_algs=get_supported_algorithms(user_agent),

        # Attestation
        attestation=AttestationConveyancePreference.DIRECT,

        # authenticatorSelection
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            require_resident_key=False, # NOTE: not supported on Android Browser
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        timeout=10000
    )

    # Save challenge in session (should use session way to handle that)
    db.set("challenge", registration_options.challenge)
    
    # inits for later usage
    if not db.get(user_id):
        db.set(user_id, "")

    # returns the options in json format
    options_json = options_to_json(registration_options)
    print("------------------ generate_registration_opts returned options")
    print(options_json)

    return options_json

########################################################################
#
#  will be called by js: parseAndValidateCredentialOnBackend()
#
########################################################################
@api.route('/verify_registration', methods=['POST'])
# to enable CORS for the example
@cross_origin()
def verify_registration():
    """To verify webauthn registration credentials"""
    
    # retrieves user id from argument
    args=request.args
    user_id=args.get("userId")
    print("------------------ verify_registration for user id")
    print(user_id)

    credential_data = request.get_json()
    user_agent=request.headers.get('User-Agent')
    
    print("------------------ verify_registration POST DATA")
    print(credential_data)

    # Parse response
    parsed_cred=RegistrationCredential.parse_raw(json.dumps(credential_data)) 

    # Example to parse client data json
    client_data_json=parse_client_data_json(parsed_cred.response.client_data_json)
    print("------------------ client_data_json")
    print(client_data_json)
    # Example to parse attestation object
    print("------------------ attestation_object")
    attestation_object=parse_attestation_object(parsed_cred.response.attestation_object)
    print(attestation_object)
    
    # SPECIFIC PARSING OF ANDROID SAFETYNET
    if (attestation_object.fmt == AttestationFormat.ANDROID_SAFETYNET):
        print("AttestationFormat.ANDROID_SAFETYNET CONTENT")
        jws = attestation_object.att_stmt.response.decode("ascii")
        jws_parts = jws.split(".")
        if len(jws_parts) != 3:
            raise InvalidRegistrationResponse(
                "Response JWS did not have three parts (SafetyNet)"
            )
        payload_bytes=base64url_to_bytes(jws_parts[1])
        payload=SafetyNetJWSPayload.parse_raw(payload_bytes)
        payload_json=payload_bytes.decode("utf-8")
        print("PAYLOAD JSON")
        print(payload_json)
        print("ctsProfileMatch: A stricter verdict of device integrity. If the value of ctsProfileMatch is true, then the profile of the device running your app matches the profile of a device that has passed Android compatibility testing and has been approved as a Google-certified Android device.")
        print("VALUE = " + str(payload.cts_profile_match))
        print("basicIntegrity: A more lenient verdict of device integrity. If only the value of basicIntegrity is true, then the device running your app likely wasn't tampered with. However, the device hasn't necessarily passed Android compatibility testing.")
        print("VALUE = " + str(payload.basic_integrity))
    
    # Gets challenge from sesssion
    expected_challenge=db.get('challenge')
    
    # Registration Response Verification including attestation verification
    registration_verification = verify_registration_response(
        credential=parsed_cred,
        expected_challenge=expected_challenge,
        expected_origin=get_expected_origin(user_agent),
        expected_rp_id=get_expected_rpid(user_agent),
        require_user_verification=True,
    )

    print("------------------ verify_registration_response result")
    print(registration_verification.json(indent=2))

    # User registered
    print("------------------ User registered, cred id")
    print(registration_verification.credential_id)

    # Store credential ID
    cred_id_base64=base64.urlsafe_b64encode(registration_verification.credential_id).decode('ascii').rstrip("=")
    user_updated_cred_ids=db.get(user_id) + "|" + cred_id_base64
    db.set(user_id, user_updated_cred_ids)
    print("USER " + user_id + " CRED IDs " + user_updated_cred_ids)

    # stores the public key
    db.set(cred_id_base64, registration_verification.credential_public_key)

    # 200
    return jsonify(success=True)

########################################################################
#
#  will be called by js: generateAuthOptionsFromBackend()
#
########################################################################
@api.route('/generate_authentication_opts', methods=['GET'])
# to enable CORS for the example
@cross_origin()
def generate_authentication_opts():
    """To generate webauthn authentication options"""

    user_agent=request.headers.get('User-Agent')

    # retrieves user id from argument
    args=request.args
    user_id=args.get("userId")
    print("------------------ generate_authentication_opts for user id")
    print(user_id)

    # get cred ids
    cred_ids = []
    user_cred_ids=db.get(user_id).split("|")
    for user_cred_id in user_cred_ids:
            if user_cred_id:
                cred_ids.append(PublicKeyCredentialDescriptor(id=base64_decode(user_cred_id)))

    # generation...
    authentication_options = generate_authentication_options(
        rp_id=get_expected_rpid(user_agent),
        allow_credentials=cred_ids,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=12000
    )

    # Save challenge in session (should use session way to handle that)
    db.set("challenge", authentication_options.challenge)

    options_json = options_to_json(authentication_options)
    
    print("------------------ generate_authentication_opts returned options")
    print(options_json)

    return options_json

########################################################################
#
#  will be called by js: parseAndValidateAssertionOnBackend()
#
########################################################################
@api.route('/verify_authentication', methods=['POST'])
# to enable CORS for the example
@cross_origin()
def verify_authentication():
    """To verify webauthn authentication"""

    # retrieves user id from argument
    args=request.args
    user_id=args.get("userId")
    print("------------------ verify_authentication for user id")
    print(user_id)
    
    assertion = request.get_json()
    user_agent=request.headers.get('User-Agent')
    print("------------------ verify_authentication POST DATA")
    print(assertion)

    # Parse response
    parsed_assertion=AuthenticationCredential.parse_raw(json.dumps(assertion))

    # Example to parse client data json
    client_data_json=parse_client_data_json(parsed_assertion.response.client_data_json)
    print(client_data_json)

    # Print some values
    print("------------------ signature size")
    print(len(parsed_assertion.response.signature))
    print("------------------ authenticator_data size")
    print(len(parsed_assertion.response.authenticator_data))
    print("------------------ parsed authenticator_data size")
    auth_data = parse_authenticator_data(parsed_assertion.response.authenticator_data)
    print(auth_data)

    # Gets challenge from sesssion
    expected_challenge=db.get('challenge')
    
    # retrieves saved public key
    public_key=db.get(parsed_assertion.id)

    authentication_verification = verify_authentication_response(
        credential=parsed_assertion,
        expected_challenge=expected_challenge,
        expected_rp_id=get_expected_rpid(user_agent),
        expected_origin=get_expected_origin(user_agent),
        credential_public_key=public_key,
        credential_current_sign_count=0,
        require_user_verification=True,
    )

    print("------------------ verify_authentication response result")
    print(authentication_verification.json(indent=2))

    # User registered
    print("------------------ new sign count")
    print(authentication_verification.new_sign_count)
    
    # 200
    return jsonify(success=True)

def get_expected_rpid(req_user_agent):
    """Will return expected origin based on request user agent"""

    if "okhttp" in req_user_agent:
        # Request comming from Android, Workaround: will use same domain as the wellknown url
        return "panoramic-warp-march.glitch.me"
    else:
        # request coming from browser
        return "webauthn-python-backend.herokuapp.com" # To make the example work on localhost, otherwise it should be: something.com

def get_expected_origin(req_user_agent):
    """Will return expected rp id based on request user agent"""

    if "okhttp" in req_user_agent:
        # Request comming from Android
        return "android:apk-key-hash:26szkDefx71uYzplqvYgGay72X_EDCe89X1zon0eaMA"
    else:
        # request coming from browser
        return "https://webauthn-python-backend.herokuapp.com"

def get_supported_algorithms(req_user_agent):
    """Will return supported algorithms based on request user agent"""

    if "okhttp" in req_user_agent:
        # Request comming from Android
        return [
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            #COSEAlgorithmIdentifier.EDDSA # NOTE: not supported on Android
        ]
    else:
        # request coming from browser
        return [
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.EDDSA
        ]

def base64_decode(string):
    """
    Adds back in the required padding before decoding.
    """
    padding = 4 - (len(string) % 4)
    string = string + ("=" * padding)
    return base64.urlsafe_b64decode(string)

if __name__ == '__main__':
    api.run(port=os.getenv('PORT'), host="0.0.0.0")
