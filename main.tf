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