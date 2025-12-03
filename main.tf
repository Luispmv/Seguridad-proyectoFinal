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