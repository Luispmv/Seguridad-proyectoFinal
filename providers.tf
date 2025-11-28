// Colocamos a aws como el proveedor de nuestra infraestructura

terraform {
  required_providers {
    aws = {
        source = "hashicorp/aws"
        version = "~> 6.0"
    }
  }
}