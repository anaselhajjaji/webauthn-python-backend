// Overrides some functions from webauthn.js
generateRegistrationOptionsFromBackend = async function () {

  let userId = document.getElementById("userId").value;

  if (userId.length == 0) {
    alert("Please fill in the user id.");
  }
  else {
    let data = await fetch(`http://localhost:8081/generate_registration_opts?userId=${userId}`)
      .then((response) => response.json())
      .then((data) => {
        // Create needs byte array instead in base64 json version
        // Some decoding here
        data.user.id = base64DecodeURL(data.user.id);
        data.challenge = base64DecodeURL(data.challenge);
        if (data.excludeCredentials) {
          for (let cred of data.excludeCredentials) {
            cred.id = base64DecodeURL(cred.id);
          }
        }
        return data;
      })
      .catch(error => {
        console.error(error);
      });
    return data;
  }
}

parseAndValidateCredentialOnBackend = async function (cred) {

  let userId = document.getElementById("userId").value;

  if (userId.length == 0) {
    alert("Please fill in the user id.");
  }
  else {

    // Prepare the response
    // encode base 64 byte arrays
    const credential = {};
    credential.id = cred.id;
    credential.rawId = base64EncodeURL(cred.rawId);
    credential.type = cred.type;

    if (cred.response) {
      const clientDataJSON = base64EncodeURL(cred.response.clientDataJSON);
      const attestationObject = base64EncodeURL(cred.response.attestationObject);
      credential.response = {
        clientDataJSON,
        attestationObject,
      };
    }

    // Call the backend
    const headers = {
      'X-Requested-With': 'XMLHttpRequest',
    };
    headers['Content-Type'] = 'application/json';
    const res = await fetch(`http://localhost:8081/verify_registration?userId=${userId}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: headers,
      body: JSON.stringify(credential),
    });
    if (res.status === 200) {

      // END: If the validation process succeeded, the server would then store the publicKeyBytes
      // and credentialId in a database, associated with the user.
      localStorage.setItem('credId', credential.id);

      // Display in screen
      const credentialDiv = document.getElementById('credential');
      credentialDiv.innerHTML = '<p><b>Credential ID:</b> ' + credential.id + '</p>';

    } else {
      // Server authentication failed
      const result = await res.json();
      throw result.error;
    }
  }
}

generateAuthOptionsFromBackend = async function (credentialId) {

  console.log("Generate auth opts for cred id", credentialId);

  let userId = document.getElementById("userId").value;

  if (userId.length == 0) {
    alert("Please fill in the user id.");
  }
  else {

    let data = await fetch(`http://localhost:8081/generate_authentication_opts?userId=${userId}`)  //encodeURIComponent(credentialId)
      .then((response) => response.json())
      .then((data) => {
        // Create needs byte array instead in base64 json version
        // Some decoding here
        data.challenge = base64DecodeURL(data.challenge);
        for (let cred of data.allowCredentials) {
          cred.id = base64DecodeURL(cred.id);
        }
        return data;
      })
      .catch(error => {
        console.error(error);
      });
    return data;
  }
}

parseAndValidateAssertionOnBackend = async function (cred) {

  let userId = document.getElementById("userId").value;

  if (userId.length == 0) {
    alert("Please fill in the user id.");
  }
  else {

    // Prepare the response
    // encode base 64 byte arrays
    const credential = {};
    credential.id = cred.id;
    credential.type = cred.type;
    credential.rawId = base64EncodeURL(cred.rawId);

    if (cred.response) {
      const clientDataJSON = base64EncodeURL(cred.response.clientDataJSON);
      const authenticatorData = base64EncodeURL(cred.response.authenticatorData);
      const signature = base64EncodeURL(cred.response.signature);
      const userHandle = base64EncodeURL(cred.response.userHandle);
      credential.response = {
        clientDataJSON,
        authenticatorData,
        signature,
        userHandle,
      };
    }

    // Call the backend
    const headers = {
      'X-Requested-With': 'XMLHttpRequest',
    };
    headers['Content-Type'] = 'application/json';
    const res = await fetch(`http://localhost:8081/verify_authentication?userId=${userId}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: headers,
      body: JSON.stringify(credential),
    });
    if (res.status === 200) {
      // Display in screen
      const authResultDiv = document.getElementById('authResult');
      authResultDiv.innerHTML = '<p><b>Auth Success!!</b></p>';
    } else {
      // Server authentication failed
      const result = await res.json();
      throw result.error;
    }
  }
}
