# app/auth/auth_handler.py

import time
from typing import Dict
import jwt
from decouple import config

# Fetch the secret and algorithm from environment variables
JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")


def token_response(token: str) -> Dict[str, str]:
    return {
        "access_token": token
    }

# Function to sign JWT token
def signJWT(user_id: str) -> Dict[str, str]:
    payload = {
        "user_id": user_id,
        "expires": time.time() + 600  # Token expiration time (600 seconds = 10 minutes)
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token_response(token)

# Function to decode JWT token
def decodeJWT(token: str) -> dict:
    try:
        # Decode the token and validate the expiration
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Check expiration time
        if decoded_token["expires"] >= time.time():
            return decoded_token
        else:
            return {}  # Token expired
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.DecodeError:
        return {"error": "Invalid token"}
    except Exception as e:
        return {"error": str(e)}  # Return any other errors that occur

