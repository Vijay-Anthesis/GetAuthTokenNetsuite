import logging
import jwt
import time
import base64
import os
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import json
from datetime import datetime, timedelta
import requests
import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    vault_url = "https://netsuiteapi.vault.azure.net/"
    secret_name = "netsuiteprivekey-sb"
    
    credential = DefaultAzureCredential()

    vault_secret = SecretClient(vault_url=vault_url, credential=credential)
    retrieved_secret = vault_secret.get_secret(secret_name)
    # logging.info(f"Retrieved secret value: {retrieved_secret.value}")

    # secret = os.environ["SECRET_KEY"]
    # secret = "-----BEGIN PRIVATE KEY-----MIIG/QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQC0IfXl9rlxlIrXUco/PKZVY+xPa7jgfafysF/EQGQJPnnqxbkhYIyt0Vi8jJJQ+rpmHvo33p3UlY3cXVb8+LPQJ1d/0HBN4xKnVEzySuhAkfLYTfmhULEFYZ/m5zaMYkwQrX5ojYz+uUi39DUQ8m1MyTlUuAWAHF0+8ffgCqtcps7zL2IaYp6tAttQUEmlxj4kuhSLUBzvgBjKs02qKf3NkaiBxjDbvNDzLqsjPiJgXlOkxGTw3EbVCT6ALRLsf5Wbr/4f51cFpfmhO2xq7uilpFbRfqcZR8QnTguvPyPioRmUxTEjYgL6lo4fHI8vj8gvdhuU/rlzTTGxIjkLgWOpvw+aPRJYFF4W9YncK7v84C4PZ7FB2OHcQhJw10ponfEdpO8JmlS6xyvt7CWr4+vEj3ym2gG2LajoDOAfsLuiw2AbzTbfjTJKfvSv9LYdSHE+qQfVialvI8WRWFvm62ULBiojtMZifx094YhcCT5rCPEhJKes/U7g7Sps9u0RftECAwEAAQKCAYAS1dE9Rk7uQDLDYIdGFPyshZoGVPR8Ls9yqjwdTIFZURnU8W9R/ONA4pjFgGplQs5eUsNlt6anvaqbffwUUBoXPCHjWMOBdWq0KfWwySHfbJNoyEB/vG0CK8rZTVhwFfAvt0B2RMTXNr8SkxvAZaUFqC3RPLvAgVbDt+/sEpmIAt41YgE/UowWeau+imKlDaVeWEHBLnOUHIAbI+QNVL438lDdHwDpXSU5JGpbMUpNateSrUGDyPi0GncZVn050v4/45JFD5dVABu8+aDIz9+DN/8xRhLX+2W9Hhaikwikj6wGZtVbHe1L5T4b1jIMJIIraDB1e1tHcq6d7y3O7dQZUFXDCO52RcoGBmKdMoFEqzexbmzqHvV7V5i6mCiAWQyENykxYT7LTv7R6bCES+qNr3n1dro9KeanazWDJ8YC0IBxHZ+wF3z4IipbqZZnZJbyB216+SOA5dPqjTcB/OWwXuJJq7vlh/t9gSD86Szv5GA4zqoot2ph98641oVFCbUCgcEA7slTb0Bt84LFcqW+tIYfdxRyPcgKm70uiQ32jB/lNEmlOvD2SuAFrbgO6cakpQtyTy7/Fp61I5alGLJOQRumXttNkZynRpIwyBIh9+1lh1GMRt0Bp1DHhEFmbIuJOjwdBNMtyjIx/V+qf+MlGJkJzG70JebzafsOGhgNfJAfc9pjtI71wh4zMEy3T2msM6Ksx3OAhovI2yN++wbHWoW86IjMzBowMfTF/mm8mQ3Hwl9d1ynGvnsg5/wDCr6pTYbNAoHBAMEeNgl7wehdb1WGeUsOrWdAWm3Xf/5685b9pH+71qDOeLWokXqle2pq0eoTzrdJm4XEMqF6pvQa7P3VGX4UrFFTsje+37V1zPiAxwcyNQ4pgG1WwXo0I3wrvgGqnEgERbWN8g2tXvLLs8p06U1j5iPfDykDR662gFf38dhN2lVGiaMrzqTuX4a2zWVTrp8hHipVJEv9RWUKOqMqKCOwL+/i9gwdBF1t/sSKF4oUwC9LrtVHtuZcob83yhGyTCswFQKBwH0ou3nRrI/5mGKqa5YVwwJYjjTB2IWfGHgwAG2b/jh07Y1CZeYDHBbdJbv1KbF0mXrVqFED6O/5cxnJw+iuhHqtui+7i5Ya5ETJ9FIOdawC22L9TnOTjLBO00/Lp6cFgTRZOGQGAVvMPAMCXRxSgudLtN70+dswA0k8GD2VEVdZPe+TC0+vIqeLXn3aZq898hAtA04CkMoEBfevquhQtx6vLaFBjMdyhCEA7SDQL0c7U2WG+Sw4P5w45KNKIlWHdQKBwCHxbHAIR5HO8mWm6CTQJJxUTFCoIwAYnj34wPQOkO/cuoy7Xy6ebW3L7q9k4d2HW4WMcZW+WB/pp6QJ05w8h/kXa+iubOWZGfjHsbPLGFYv5znQmNsg1OfbTF9AnI1v6sy5cUUEJv8n3KcGG4eVunqtlx2PTQchXreXhfON44U/i6uZZI3KtBGaicl4huXDTWkFZAbTMmJLBPluzHVRX2ubicGhTAYb8j6bQv3rHchyVf14yGX+/BL+/E5V91tT7QKBwQCUdvXMfnhM1q85cfr79jUQeGR4vtPFQ8+E6+1t+gBuuFuGYiNVIfW6z8R5NJ27ha986MdRYSj4yEVED1c8Efx+vD3qcqK+YtBf30hX6rPvKCQocbyTjwfuvgt+lDgXhX9EjIY2AET7ZxYInJT4c6PFdDwfG0+K9OXiDtTWTJFJxZtFQnR3swHebNGhl8v7UP2n7di2SqBloVezJTJNpcWalBXyTjGv8rN5Y00gw5t1aIhoJ9myw72JX5whcDf3M/Q=-----END PRIVATE KEY-----"
    try:
        secret_bytes = b''
        # secret_bytes = base64.b64decode(retrieved_secret.value)
        secret_bytes = base64.b64decode(retrieved_secret.value)
    except base64.binascii.Error:
        secret_bytes = retrieved_secret.value.encode('utf-8')
    except Exception as e:
        logging.error(f"error decoded b64: {e}")


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

    private_key = serialization.load_pem_private_key(secret_bytes, password=None, backend=default_backend())

    jwt_assertion = jwt.encode(payload, secret_bytes, algorithm='RS256', headers=header)

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
        return func.HttpResponse(json.dumps(response.json()), status_code=200, mimetype="application/json")
    else:
        return func.HttpResponse(f"Error: {response.status_code} {response.text}", status_code=response.status_code)
