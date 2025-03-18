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