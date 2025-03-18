# Securing API Gateway with Lambda Authorizer Using JWT Tokens


### Introduction

In an earlier post, we explored deploying a REST API using API Gateway, AWS Lambda, DynamoDB, and Terraform. The architecture consisted of:
1. An API Gateway exposing the REST API endpoints.
2. AWS Lambda handling backend logic.
3. DynamoDB serving as the database.

However, one critical security issue was that anyone with the API invoke URL could access the API and perform operations. To restrict API access, various approaches can be considered:
1. **API Gateway Resource Policies**: Restrict access to specific AWS accounts or IP ranges.
2. **IAM Authorization**: Require clients to sign requests with AWS IAM credentials.
3. **Cognito User Pools**: Implement user authentication and authorization with Amazon Cognito.
4. **Lambda Authorizers**: Use a custom Lambda function to validate authorization logic before allowing access.

In this tutorial, we will focus on securing the API using a Lambda Authorizer with JSON Web Tokens (JWTs).

### What is a JWT Token?

A JSON Web Token (JWT) is a compact, URL-safe token format used for authentication and authorization. It consists of three parts:
1. **Header**: Contains metadata such as the token type and signing algorithm.
2. **Payload**: Holds claims (information) about the user, such as user ID and permissions.
3. **Signature**: Ensures the token's integrity, created using a secret key or public/private key pair.

JWTs are widely used in authentication flows, where a client receives a token upon login and uses it to access protected resources.

### Architecture
Follwing is the serverless architecture we will be dealing with.

## Step 1: Create Lambda IAM Role with Lambda Function
We setup required IAM Role for Lambda Function to access DynamoDB to perform CRUD operations.
```terraform
################################################################################
# Lambda IAM role to assume the role
################################################################################
resource "aws_iam_role" "lambda_role" {
  name = "lambda_execution_role"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Effect" : "Allow",
      "Principal" : {
        "Service" : "lambda.amazonaws.com"
      },
      "Action" : "sts:AssumeRole"
    }]
  })
}

################################################################################
# Create policy to acess the DynamoDB
################################################################################
resource "aws_iam_policy" "DynamoDBAccessPolicy" {
  name        = "DynamoDBAccessPolicy"
  description = "DynamoDBAccessPolicy"
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : [
            "dynamodb:List*",
            "dynamodb:DescribeReservedCapacity*",
            "dynamodb:DescribeLimits",
            "dynamodb:DescribeTimeToLive"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "dynamodb:BatchGet*",
            "dynamodb:DescribeStream",
            "dynamodb:DescribeTable",
            "dynamodb:Get*",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:BatchWrite*",
            "dynamodb:CreateTable",
            "dynamodb:Delete*",
            "dynamodb:Update*",
            "dynamodb:PutItem"
          ],
          "Resource" : [
            "arn:aws:dynamodb:*:*:table/Books_Table"
          ],
          "Effect" : "Allow"
        }
      ]
    }
  )
}

################################################################################
# Assign policy to the role
################################################################################
resource "aws_iam_policy_attachment" "lambda_basic_execution" {
  name       = "lambda_basic_execution"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy_attachment" "lambda_dynamodb_access" {
  name       = "lambda_dynamodb_access"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = aws_iam_policy.DynamoDBAccessPolicy.arn
}

################################################################################
# Compressing lambda function code
################################################################################
data "archive_file" "lambda_function_archive" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda_function.zip"
}

################################################################################
# Creating Lambda Function
################################################################################
resource "aws_lambda_function" "book_lambda_function" {
  function_name = "Books_Lambda"
  filename      = "${path.module}/lambda_function.zip"

  runtime     = "python3.12"
  handler     = "lambda_function.lambda_handler"
  memory_size = 128
  timeout     = 10

  environment {
    variables = {
      DYNAMODB_TABLE = "Books_Table"
    }
  }

  source_code_hash = data.archive_file.lambda_function_archive.output_base64sha256

  role = aws_iam_role.lambda_role.arn
}

################################################################################
# Creating CloudWatch Log group for Lambda Function
################################################################################
resource "aws_cloudwatch_log_group" "book_lambda_function_cloudwatch" {
  name              = "/aws/lambda/${aws_lambda_function.book_lambda_function.function_name}"
  retention_in_days = 7
}
```
The python lambda function for CRUD operations as follows:

```python
import os
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal
import logging
import json

# Configure logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define API paths
book_path = '/book'
books_path = '/books'

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.getenv('DYNAMODB_TABLE'))

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    try: 
        http_method = event.get('httpMethod')
        path = event.get('path')
        # Handle GET Request - Fetch All Books
        if http_method == 'GET' and path == books_path:
            return get_all_books()
            
        # Handle GET Request - Fetch a Single Book
        elif http_method == 'GET' and path == book_path:
            params = event.get('queryStringParameters')
            if not params or 'book_id' not in params:
                return generate_response(400, 'Missing required parameter: book_id')

            return get_book(params['book_id'])
        
        # Handle POST Request - Save a New Book
        elif http_method == 'POST' and path == book_path:
            body = parse_request_body(event)
            if not body or 'book_id' not in body:
                return generate_response(400, 'Missing required field: book_id')
            
            return save_book(body)
            
        # Handle PATCH Request - Update a Book
        elif http_method == 'PATCH' and path == book_path:
            body = parse_request_body(event)
            if not body or 'book_id' not in body or 'update_key' not in body or 'update_value' not in body:
                return generate_response(400, 'Missing required fields: book_id, update_key, update_value')
            
            return update_book(body['book_id'], body['update_key'], body['update_value'])
            
        # Handle DELETE Request - Delete a Book
        elif http_method == 'DELETE':
            body = parse_request_body(event)
            if not body or 'book_id' not in body:
                return generate_response(400, 'Missing required field: book_id')
            
            return delete_book(body['book_id'])

        return generate_response(404, 'Resource Not Found')
                
    except ClientError as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return generate_response(500, 'Internal Server Error')

# Handle GET Request - Fetch a Single Book
def get_book(book_id):
    try:
        response = table.get_item(Key={'book_id': book_id})
        if 'Item' not in response:
            logger.warning(f"Book not found: {book_id}")
            return generate_response(404, f'Book with ID {book_id} not found')

        logger.info(f"GET book: {response['Item']}")
        return generate_response(200, response['Item'])

    except ClientError as e:
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error fetching book from database')

# Handle GET Request - Fetch All Books
def get_all_books():
    try:
        scan_params = {
            'TableName': table.name
        }
        items = recursive_scan(scan_params, [])
        logger.info('GET ALL items: {}'.format(items))
        return generate_response(200, items)
    
    except ClientError as e:
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error fetching books from database')

# Recursive function to scan all items in DynamoDB table    
def recursive_scan(scan_params, items):
    response = table.scan(**scan_params)
    items += response['Items']
    if 'LastEvaluatedKey' in response:
        scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
        recursive_scan(scan_params, items)
    return items

# Handle POST Request - Save a New Book
def save_book(item):
    try:
        response = table.put_item(Item=item)
        return generate_response(201, {'Message': 'Book saved successfully', 'Item': item})

    except ClientError as e:
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error saving book')
    
# Handle PATCH Request - Update a Book    
def update_book(book_id, update_key, update_value):
    try:
        response = table.update_item(
            Key={'book_id': book_id},
            UpdateExpression=f'SET {update_key} = :value',
            ExpressionAttributeValues={':value': update_value},
            ConditionExpression='attribute_exists(book_id)',  # Ensure item exists
            ReturnValues='UPDATED_NEW'
        )
        return generate_response(200, {'Message': 'Book updated successfully', 'UpdatedAttributes': response['Attributes']})

    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.warning(f"Update failed: Book with ID {book_id} does not exist")
            return generate_response(404, f'Book with ID {book_id} not found')
        
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error updating book')
    
# Handle DELETE Request - Delete a Book    
def delete_book(book_id):
    try:
        response = table.delete_item(
            Key={'book_id': book_id},
            ReturnValues='ALL_OLD'
        )
        if 'Attributes' not in response:
            return generate_response(404, f'Book with ID {book_id} not found')

        return generate_response(200, {'Message': 'Book deleted successfully', 'DeletedItem': response['Attributes']})

    except ClientError as e:
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error deleting book')

# Helper functions - Parse Request Body and Generate Response
def parse_request_body(event):
    try:
        return json.loads(event.get('body', '{}'))
    except json.JSONDecodeError:
        return None

# Custom JSON Encoder to handle Decimal types
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            if obj % 1 == 0:
                return int(obj)
            else:
                return float(obj)
        return super(DecimalEncoder, self).default(obj)

# Generate API response
def generate_response(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'status': status_code, 'data': body}, cls=DecimalEncoder)
    }
```

### Step 2: Setup DynamoDB Table
Create a DynamoDB table for storing book records. And create sample records from books.json
```terraform
################################################################################
# Creating DynamoDB table
################################################################################
resource "aws_dynamodb_table" "books_table" {
  name           = "Books_Table"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "book_id"

  attribute {
    name = "book_id"
    type = "S"
  }
}

################################################################################
# Creating DynamoDB table items
################################################################################
locals {
  json_data = file("${path.module}/books.json")
  books     = jsondecode(local.json_data)
}

resource "aws_dynamodb_table_item" "books" {
  for_each   = local.books
  table_name = aws_dynamodb_table.books_table.name
  hash_key   = aws_dynamodb_table.books_table.hash_key
  item       = jsonencode(each.value)
}
```

### Step 3: Setup API Gateway with required methonds
The API Gateway functions as a proxy, forwarding incoming HTTP requests from the client to the Lambda function using a POST request.

API Gateway methods will have "CUSTOM" Authorization with a lambda authorizer attached to it (created in step 4).

```terraform
################################################################################
# API gateway
################################################################################
resource "aws_api_gateway_rest_api" "API-gateway" {
  name        = "lambda_rest_api"
  description = "This is the REST API for Best Books"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

################################################################################
# API resource for the path "/book"
################################################################################
resource "aws_api_gateway_resource" "API-resource-book" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  parent_id   = aws_api_gateway_rest_api.API-gateway.root_resource_id
  path_part   = "book"
}

################################################################################
# API resource for the path "/books"
################################################################################
resource "aws_api_gateway_resource" "API-resource-books" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  parent_id   = aws_api_gateway_rest_api.API-gateway.root_resource_id
  path_part   = "books"
}

################################################################################
# Lambda Authorizer
################################################################################
resource "aws_api_gateway_authorizer" "my_authorizer" {
  name                             = "my_authorizer"
  rest_api_id                      = aws_api_gateway_rest_api.API-gateway.id
  authorizer_uri                   = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/${aws_lambda_function.lambda_authorizer.arn}/invocations"
  identity_source                  = "method.request.header.authorizationToken"
  authorizer_result_ttl_in_seconds = 0
}

################################################################################
## GET /book/{bookId}
################################################################################

resource "aws_api_gateway_method" "GET_one_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gateway.id
  resource_id   = aws_api_gateway_resource.API-resource-book.id
  http_method   = "GET"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.my_authorizer.id
}

resource "aws_api_gateway_integration" "GET_one_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gateway.id
  resource_id             = aws_api_gateway_resource.API-resource-book.id
  http_method             = aws_api_gateway_method.GET_one_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "GET_one_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.GET_one_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true,
    "method.response.header.Access-Control-Allow-Methods"     = true,
    "method.response.header.Access-Control-Allow-Origin"      = true,
    "method.response.header.Access-Control-Allow-Credentials" = true
  }
}

resource "aws_api_gateway_integration_response" "GET_one_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.GET_one_method.http_method
  status_code = aws_api_gateway_method_response.GET_one_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.GET_one_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": $input.path('$.statusCode'),
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}

################################################################################
## GET ALL /books 
################################################################################

resource "aws_api_gateway_method" "GET_all_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gateway.id
  resource_id   = aws_api_gateway_resource.API-resource-books.id
  http_method   = "GET"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.my_authorizer.id
}

resource "aws_api_gateway_integration" "GET_all_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gateway.id
  resource_id             = aws_api_gateway_resource.API-resource-books.id
  http_method             = aws_api_gateway_method.GET_all_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "GET_all_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-books.id
  http_method = aws_api_gateway_method.GET_all_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true,
    "method.response.header.Access-Control-Allow-Methods"     = true,
    "method.response.header.Access-Control-Allow-Origin"      = true,
    "method.response.header.Access-Control-Allow-Credentials" = true
  }
}

resource "aws_api_gateway_integration_response" "GET_all_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-books.id
  http_method = aws_api_gateway_method.GET_all_method.http_method
  status_code = aws_api_gateway_method_response.GET_all_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.GET_all_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": 200,
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}

################################################################################
## POST /book
################################################################################

resource "aws_api_gateway_method" "POST_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gateway.id
  resource_id   = aws_api_gateway_resource.API-resource-book.id
  http_method   = "POST"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.my_authorizer.id
}

resource "aws_api_gateway_integration" "POST_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gateway.id
  resource_id             = aws_api_gateway_resource.API-resource-book.id
  http_method             = aws_api_gateway_method.POST_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "POST_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.POST_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true,
    "method.response.header.Access-Control-Allow-Methods"     = true,
    "method.response.header.Access-Control-Allow-Origin"      = true,
    "method.response.header.Access-Control-Allow-Credentials" = true
  }
}

resource "aws_api_gateway_integration_response" "POST_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.POST_method.http_method
  status_code = aws_api_gateway_method_response.POST_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.POST_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": 200,
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}

################################################################################
## PATCH /book
################################################################################

resource "aws_api_gateway_method" "PATCH_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gateway.id
  resource_id   = aws_api_gateway_resource.API-resource-book.id
  http_method   = "PATCH"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.my_authorizer.id
}

resource "aws_api_gateway_integration" "PATCH_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gateway.id
  resource_id             = aws_api_gateway_resource.API-resource-book.id
  http_method             = aws_api_gateway_method.PATCH_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "PATCH_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.PATCH_method.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "PATCH_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.PATCH_method.http_method
  status_code = aws_api_gateway_method_response.PATCH_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.PATCH_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": 200,
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}

################################################################################
## DELETE /book
################################################################################

resource "aws_api_gateway_method" "DELETE_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gateway.id
  resource_id   = aws_api_gateway_resource.API-resource-book.id
  http_method   = "DELETE"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.my_authorizer.id
}

resource "aws_api_gateway_integration" "DELETE_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gateway.id
  resource_id             = aws_api_gateway_resource.API-resource-book.id
  http_method             = aws_api_gateway_method.DELETE_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "DELETE_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.DELETE_method.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "DELETE_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.DELETE_method.http_method
  status_code = aws_api_gateway_method_response.DELETE_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.DELETE_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": 200,
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}


################################################################################
# Setup Lambda permission to allow API Gateway to invoke the Lambda function
################################################################################
resource "aws_lambda_permission" "allow_api_gateway_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.book_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.API-gateway.execution_arn}/*/*"
}

################################################################################
# Setup Lambda permission to allow API Gateway to invoke the Lambda function
################################################################################
resource "aws_lambda_permission" "allow_api_gateway_invoke_authorizer" {
  statement_id  = "AllowAPIGatewayInvoke_authorizer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.API-gateway.execution_arn}/*/*"
}

################################################################################
# Deployment of the API Gateway
################################################################################
resource "aws_api_gateway_deployment" "example" {

  depends_on = [
    aws_api_gateway_integration.GET_one_lambda_integration,
    aws_api_gateway_integration.GET_all_lambda_integration,
    aws_api_gateway_integration.PATCH_lambda_integration,
    aws_api_gateway_integration.POST_lambda_integration,
    aws_api_gateway_integration.DELETE_lambda_integration
  ]

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.API-resource-book,
      aws_api_gateway_method.GET_one_method,
      aws_api_gateway_integration.GET_one_lambda_integration,
      aws_api_gateway_method.GET_all_method,
      aws_api_gateway_integration.GET_all_lambda_integration,
      aws_api_gateway_method.POST_method,
      aws_api_gateway_integration.POST_lambda_integration,
      aws_api_gateway_method.PATCH_method,
      aws_api_gateway_integration.PATCH_lambda_integration,
      aws_api_gateway_method.DELETE_method,
      aws_api_gateway_integration.DELETE_lambda_integration
    ]))
  }

  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
}

################################################################################
# Create a stage for the API Gateway
################################################################################
resource "aws_api_gateway_stage" "my-prod-stage" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.API-gateway.id
  stage_name    = "prod"

  # depends_on = [aws_cloudwatch_log_group.api_gateway_execution_logs]

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway_execution_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      responseLength = "$context.responseLength"
    })
  }
}


################################################################################
# Method settings
################################################################################
resource "aws_api_gateway_method_settings" "method_settings" {
  rest_api_id = aws_api_gateway_rest_api.API-gateway.id
  stage_name  = aws_api_gateway_stage.my-prod-stage.stage_name
  method_path = "*/*"
  settings {
    logging_level      = "INFO"
    data_trace_enabled = true
    metrics_enabled    = true
  }
}

################################################################################
# CloudWatch log group for api execution logs
################################################################################
resource "aws_cloudwatch_log_group" "api_gateway_execution_logs" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.API-gateway.id}/prod"
  retention_in_days = 7
}
```

### Step 4: Define Lambda Authorizer Function Code
A Lambda Authorizer is a custom AWS Lambda function that inspects API requests and determines whether they should be allowed or denied. We have used `TOKEN` based lambda authorizer. Below is a Python implementation of a Lambda Authorizer that verifies a JWT token:

```python
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
```

To decode JWT we will use the PyJWT library. AWS Lambda environmnet does not have the PyJWT package by default. Therefore, we need to upload all the packages needed for the lambda_handler function to run in a zip file. Steps are as below:
1. Go to lambda_authorizer directory at terminal
2. Run command `pip install --target ./ PyJWT`

Then directory structure will look like this:

![alt text](/images/authorizer_code_dir.png)

Then we create zip file and create a lambda function for authorizer along wih IAM role:

```terraform
################################################################################
# Lambda IAM role to assume the role
################################################################################
resource "aws_iam_role" "lambda_authorizer_role" {
  name = "lambda_auth_execution_role"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Effect" : "Allow",
      "Principal" : {
        "Service" : "lambda.amazonaws.com"
      },
      "Action" : "sts:AssumeRole"
    }]
  })
}

################################################################################
# Assign policy to the role
################################################################################
resource "aws_iam_policy_attachment" "lambda_basic_execution_authorizer" {
  name       = "lambda_basic_execution_authorizer"
  roles      = [aws_iam_role.lambda_authorizer_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

################################################################################
# Compressing lambda authorizer code
################################################################################
data "archive_file" "lambda_authorizer_archive" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_authorizer"
  output_path = "${path.module}/lambda_authorizer.zip"
}

################################################################################
# Creating Lambda authorizer
################################################################################
resource "aws_lambda_function" "lambda_authorizer" {
  function_name = "LambdaAuthorizer"
  filename      = "${path.module}/lambda_authorizer.zip"

  runtime     = "python3.12"
  handler     = "lambda_authorizer.lambda_handler"
  memory_size = 128
  timeout     = 10

  source_code_hash = data.archive_file.lambda_authorizer_archive.output_base64sha256

  role = aws_iam_role.lambda_authorizer_role.arn

  environment {
    variables = {
      JWT_SECRET_KEY = "secret_api_tutorial"
    }
  }
}

################################################################################
# Creating CloudWatch Log group for Lambda Function
################################################################################
resource "aws_cloudwatch_log_group" "book_lambda_authorizer_cloudwatch" {
  name              = "/aws/lambda/${aws_lambda_function.lambda_authorizer.function_name}"
  retention_in_days = 7
}
```

Key Points About Lambda Authorizers
1. Authorizers Must Return an IAM Policy: Lambda Authorizers do not return HTTP responses; instead, they generate an IAM policy specifying whether access is allowed or denied.
2. Handling Denied Requests: If the response includes an explicit "Deny", AWS API Gateway returns a generic 403 error message. To customize this, experiment with returning an "Allow" policy with no actions or resources. But this is not recommended.

We have created 3 cloudwatch log groups, which will help use to scan the logs whenever required.
1. For the Lambda Function performing CRUD operations.
2. For Lambda Authorizer.
3. API gateway invokations.


### Steps to Run Terraform
Follow these steps to execute the Terraform configuration:
```terraform
terraform init
terraform plan 
terraform apply -auto-approve
```

Upon successful completion, Terraform will provide relevant outputs.
```terraform
Apply complete! Resources: 46 added, 0 changed, 0 destroyed.
```

### Testing


### Cleanup
Remember to stop AWS components to avoid large bills.
```terraform
terraform destroy -auto-approve
```

### Conclusion

By integrating a Lambda Authorizer with JWT-based authentication and deploying it using Terraform, we can enforce access control on API Gateway endpoints, ensuring only authorized users can access the API. This method is flexible and allows for various authentication mechanisms, including third-party identity providers.

### References
1. API Gateway Lambda Authorizer: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html
1. JWT Tokens: https://jwt.io/
