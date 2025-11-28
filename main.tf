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