# A simple token-based authorizer example to demonstrate how to use an authorization token
# to allow or deny a request. In this example, the caller named 'user' is allowed to invoke
# a request if the client-supplied token value is 'allow'. The caller is not allowed to invoke
# the request if the token value is 'deny'. If the token value is 'unauthorized' or an empty
# string, the authorizer function returns an HTTP 401 status code. For any other token value,
# the authorizer returns an HTTP 500 status code.
# Note that token values are case-sensitive.
import logging
import json
import jwt

SECRET = "qwertyuiopasdfghjklzxcvbnm123456"

def lambda_handler(event, context):
    try:
        auth_token = event['authorizationToken']
        user_details = decode_auth_token(auth_token)
        if user_details:
            print('authorized')
            response = generatePolicy('user', 'Allow', event['methodArn'])
        else:
            print('unauthorized')
            response = generatePolicy('user', 'Deny', event['methodArn'])

    except Exception as e:
        logging.exception(e)
        return { 'error': f"{type(e).__name__}:{e}"}

    try:
        return json.loads(response)
    except BaseException:
        print('unauthorized')
        return 'unauthorized'  # Return a 500 error


def generatePolicy(principalId, effect, resource):
    authResponse = {}
    authResponse['principalId'] = principalId
    if (effect and resource):
        policyDocument = {}
        policyDocument['Version'] = '2012-10-17'
        policyDocument['Statement'] = []
        statementOne = {}
        statementOne['Action'] = 'execute-api:Invoke'
        statementOne['Effect'] = effect
        statementOne['Resource'] = resource
        policyDocument['Statement'] = [statementOne]
        authResponse['policyDocument'] = policyDocument
    authResponse['context'] = {
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": True
    }
    authResponse_JSON = json.dumps(authResponse)
    return authResponse_JSON

def decode_auth_token(auth_token: str):
    try:
        # remove "Bearer " from the token string.
        auth_token = auth_token.replace('Bearer ', '')
        return jwt.decode(jwt=auth_token, key=SECRET, algorithms=["HS256"],options={'verify_signature': False})
    except jwt.ExpiredSignatureError:
        'Signature expired. Please log in again.'
        return
    except jwt.InvalidTokenError:
        'Invalid token. Please log in again.'
        return