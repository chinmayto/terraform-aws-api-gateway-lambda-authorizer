import jwt
import os

def lambda_handler(event, context):
    try:
        secret_key = os.environ["JWT_SECRET_KEY"]
        auth_token = event.get('authorizationToken')
        if not auth_token:
            print("Error: No authorization token provided")
            return generatePolicy("user", "Deny", event.get("methodArn"), "Unauthorized: No token provided")

        user_details = decode_auth_token(auth_token, secret_key)

        if user_details.get('Name') == "Chinmay" and user_details.get('Role') == "api_user":
            print('Authorized JWT Token')
            return generatePolicy('user', 'Allow', event['methodArn'], "Authorized : Valid JWT Token")

    except jwt.ExpiredSignatureError:
        print("Error: Token has expired")
        return generatePolicy("user", "Deny", event.get("methodArn"), "Error: Token has expired")

    except jwt.InvalidTokenError:
        print("Error: Invalid token")
        return generatePolicy("user", "Deny", event.get("methodArn"), "Error: Invalid JWT Token")

    except Exception as e:
        print(f"Lambda Error: {str(e)}")  # Log exact error
        return generatePolicy("user", "Deny", event.get("methodArn"), f"Lambda Error: {str(e)}")

def generatePolicy(principalId, effect, resource, message):
    authResponse = {
        'principalId': principalId,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        },
        "context": {
            "errorMessage": message
        }
    }
    return authResponse

def decode_auth_token(auth_token: str, secret_key: str):
    auth_token = auth_token.replace('Bearer ', '')
    return jwt.decode(jwt=auth_token, key=secret_key, algorithms=["HS256"], options={"verify_signature": False, "verify_exp": True})