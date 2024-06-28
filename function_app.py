import logging
import jwt
import time
import base64
import os
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import requests
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    secret = os.environ["SECRET_KEY"]
    secret_bytes = base64.b64decode(secret)

    url = "https://3487287-sb3.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token"

    header = {
        "alg": 'PS256',
        "typ": 'JWT',
        "kid": '7qvfiCJSniXiSy2BAiwu72m1kTFFut256F1YZndp2PA'
    }

    payload = {
        "iss": '12b3351b7e8bf09700bff5f6c230609f646ab4b4c0d2aca66dc6f3a2d7837185',
        "scope": 'rest_webservices',
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "aud": 'https://3487287-sb3.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token'
    }

    private_key = load_pem_private_key(secret_bytes, password=None, backend=default_backend())

    jwt_assertion = jwt.encode(payload, private_key, algorithm='PS256', headers=header)

    headers_for_request = {
        "Content-type": "application/x-www-form-urlencoded"
    }

    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": jwt_assertion
    }

    response = requests.post(url, headers=headers_for_request, data=data)

    if response.status_code == 200:
        return func.HttpResponse(response.json(), status_code=200)
    else:
        return func.HttpResponse(f"Error: {response.status_code} {response.text}", status_code=response.status_code)
