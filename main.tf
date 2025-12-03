// Creacion de una llave CMK (Customer Managed Key) en KMS
resource "aws_kms_key" "aws_cmk_resource" {
    description = "CMK para utilizar en S3"
    deletion_window_in_days = 7
    enable_key_rotation = true
    key_usage = "ENCRYPT_DECRYPT"
    tags = {
      "Name" = "CMK S3" 
    }
    policy = data.aws_iam_policy_document.kms_policy.json
}

// Definiendo una key polici para que S3 pueda utilizar la CMK
data "aws_iam_policy_document" "kms_policy" {
  statement {
    sid = "EnableIAMUserPermissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::945356073292:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowS3UseOfTheKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["arn:aws:s3:::pablo-bucket-seguro"]
    }
  }
}


// Creacion de un bucket de S3
resource "aws_s3_bucket" "aws_s3_resource" {
    bucket = "lpmv-77802" // Aqui definimos el nombre real del bucket de S3.
    // Añadimos etiquetas para identificar el proyecto en AWS.
    tags = {
      Name = "terraform_s3_bucket"
    }
}

// Agregando versionamiento al bucekt de S3
resource "aws_s3_bucket_versioning" "aws_s3_resource" {
    bucket = aws_s3_bucket.aws_s3_resource.id

    versioning_configuration {
      status = "Enabled"
    }
}

// Imprimimos el arn del bucket
output "lpmv-77802" {
    description = "ARN del bucket S3"
    value = aws_s3_bucket.aws_s3_resource.arn
}

// Cifrado prdeterminado del bucket S3 utilizando la clave CMK creada anteriormente
resource "aws_s3_bucket_server_side_encryption_configuration" "aws_cmk_encryption_resource" {
    bucket = aws_s3_bucket.aws_s3_resource.id
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
        kms_master_key_id = aws_kms_key.aws_cmk_resource.arn
      }
    }
}


// Autenticacion por MFA
resource "aws_s3_bucket_policy" "aws_s3_resource" {
    bucket = aws_s3_bucket.aws_s3_resource.id

    policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
        Sid       = "DenyObjectDeletionWithoutMFA"
        Effect    = "Deny"
        Principal = "*"
        Action = [
            "s3:DeleteObject",
            "s3:DeleteObjectVersion"
        ]
        Resource = "${aws_s3_bucket.aws_s3_resource.arn}/*"
        Condition = {
            Bool = {
            "aws:MultiFactorAuthPresent" = "false"
            }
            StringEquals = {
            "aws:PrincipalType" = "User"  # Solo aplica a usuarios IAM (no roles)
            }
        }
        }
    ]
    })
}




// DESARROLLO Y DESPLIEGUE DE LA API

// Permitiendo a un rol de IAM ser asumido por lambda
data "aws_iam_policy_document" "aws_iampolicy_data" {
    statement {
        effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
    }
}

// Creacion del IAM Role para Lambda
resource "aws_iam_role" "aws_iamrole_resource" {
    name = "aws_iam_role_lambda"
    assume_role_policy = data.aws_iam_policy_document.aws_iampolicy_data.json
}

// Creacion del documento IAM Policy con S3 y KMS
data "aws_iam_policy_document" "aws_iampolicys3cmk_data" {
    
  # ----- Permisos S3 -----
  statement {
    sid    = "S3Access"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:DeleteObject"
    ]

    resources = [
    #   "arn:aws:s3:::pablo-bucket-seguro/*"
    aws_s3_bucket.aws_s3_resource.arn
    ]
  }

  # ----- Permisos para usar la CMK -----
  statement {
    sid    = "KMSAccess"
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = [
    #   aws_kms_key.my_cmk.arn
    aws_kms_key.aws_cmk_resource.arn
    ]
  }
}


// Creacion de la politica 
resource "aws_iam_policy" "aws_iampolicylambda_resource" {
    name = "lambda_s3_kms_access"
    policy = data.aws_iam_policy_document.aws_iampolicys3cmk_data.json
}

// Adjuntar la politica al rol
resource "aws_iam_role_policy_attachment" "aws_iamattachrole_resource" {
    role = aws_iam_role.aws_iamrole_resource.name
    policy_arn = aws_iam_policy.aws_iampolicylambda_resource.arn
}



// Recurso de funcion lambda 
resource "aws_lambda_function" "aws_lambda_resource" {
    function_name = "lambda_api_code"
    role = aws_iam_role.aws_iamrole_resource.arn
    handler = "app.lambda_handler"
    runtime = "python3.12"

    filename = "${path.module}/lambda/lambda.zip"
    source_code_hash = filebase64sha256("${path.module}/lambda/lambda.zip")
}