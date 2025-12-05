# Proyecto de Infraestructura Segura en AWS con Terraform

## 📋 Descripción del Proyecto

Este proyecto implementa una infraestructura segura en AWS utilizando Terraform para gestionar archivos en S3 mediante una API REST. La solución incluye múltiples capas de seguridad, cifrado, versionamiento, protección WAF y backups automatizados.

## 🏗️ Arquitectura

La infraestructura está compuesta por los siguientes componentes principales:

```
┌─────────────┐
│   Cliente   │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  AWS WAF v2     │ ◄─── Protección contra ataques
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  API Gateway    │ ◄─── REST API (POST /upload, DELETE /delete)
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Lambda Function│ ◄─── Procesamiento de solicitudes
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  S3 Bucket      │ ◄─── Almacenamiento de archivos
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  KMS CMK        │ ◄─── Cifrado de datos
└─────────────────┘

┌─────────────────┐
│  AWS Backup     │ ◄─── Backups automatizados semanales
└─────────────────┘
```

## 🔧 Componentes Implementados

### 1. Amazon S3 Bucket
- **Nombre**: `lpmv-77802`
- **Región**: `us-west-2` (Oregón)
- **Características**:
  - Versionamiento habilitado
  - Cifrado con KMS CMK
  - Política de bucket que requiere MFA para eliminar objetos
  - Protección contra eliminación accidental

### 2. AWS KMS (Customer Managed Key)
- **Descripción**: CMK para cifrado de datos en S3
- **Características**:
  - Rotación automática de claves habilitada
  - Ventana de eliminación: 7 días
  - Política IAM restringida para uso por S3
  - Uso: ENCRYPT_DECRYPT

### 3. AWS Lambda Function
- **Nombre**: `lambda_api_code`
- **Runtime**: Python 3.12
- **Handler**: `app.handler`
- **Permisos**:
  - Acceso mínimo a S3 (PutObject, DeleteObject)
  - Permisos KMS para cifrado/descifrado
  - Principio de privilegios mínimos aplicado

### 4. API Gateway REST API
- **Nombre**: `aws_api_gateway_resource`
- **Endpoints**:
  - `POST /upload` - Subir archivos a S3
  - `DELETE /delete` - Eliminar archivos de S3
- **Stage**: `prod`
- **Integración**: AWS_PROXY con Lambda

### 5. AWS WAF v2
- **Nombre**: `api-gateway-waf`
- **Reglas implementadas**:
  1. **Rate Limiting**: Limita a 10 solicitudes por IP para mitigar ataques de fuerza bruta
  2. **Bloqueo de DELETE**: Bloquea solicitudes DELETE que contengan:
     - Ruta `/delete`
     - Patrón `DELETE_BLOCK_TRIGGER` en el cuerpo
     - Respuesta: 403 Forbidden
- **Métricas**: CloudWatch habilitado para monitoreo

### 6. AWS Backup
- **Vault**: `s3-backup-vault`
- **Plan**: `s3-backup-plan`
- **Configuración**:
  - Frecuencia: Semanal (martes a las 18:00 UTC)
  - Retención: 75 días
  - Cifrado: Utiliza la CMK de KMS
  - Recurso protegido: Bucket S3

### 7. IAM Roles y Políticas
- **Rol Lambda**: `aws_iam_role_lambda`
  - Política de confianza restringida al servicio Lambda
  - Permisos mínimos para S3 y KMS
- **Rol Backup**: `aws-backup-service-role`
  - Permisos para ejecutar backups de S3

## 💻 Implementación en Terraform

Esta sección muestra el código Terraform utilizado para implementar cada componente.

### Configuración del Proveedor

```1:9:providers.tf
terraform {
  required_providers {
    aws = {
        source = "hashicorp/aws"
        version = "~> 6.0"
    }
  }
}
```

### Variables

```1:6:variables.tf
variable "aws_region" {
    description = "Region de AWS"
    type = string
    default = "us-west-2"
}
```

### 1. KMS Customer Managed Key (CMK)

Creación de la clave CMK con política IAM que permite su uso por S3:

```2:53:main.tf
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
```

### 2. S3 Bucket con Versionamiento

Creación del bucket S3 con versionamiento habilitado:

```57:72:main.tf
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
```

### 3. Cifrado del Bucket S3 con KMS

Configuración del cifrado del bucket utilizando la CMK:

```81:89:main.tf
resource "aws_s3_bucket_server_side_encryption_configuration" "aws_cmk_encryption_resource" {
    bucket = aws_s3_bucket.aws_s3_resource.id
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
        kms_master_key_id = aws_kms_key.aws_cmk_resource.arn
      }
    }
}
```

### 4. Política de Bucket que Requiere MFA

Política que previene la eliminación de objetos sin autenticación MFA:

```93:119:main.tf
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
```

### 5. IAM Role para Lambda

Creación del rol IAM con política de confianza y permisos mínimos:

```127:194:main.tf
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
    "${aws_s3_bucket.aws_s3_resource.arn}/*"
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
```

### 6. Función Lambda

Implementación de la función Lambda con integración de código:

```199:213:main.tf
resource "aws_lambda_function" "aws_lambda_resource" {
    function_name = "lambda_api_code"
    role = aws_iam_role.aws_iamrole_resource.arn
    handler = "app.handler"
    runtime = "python3.12"

    filename = "${path.module}/lambda/lambda.zip"
    source_code_hash = filebase64sha256("${path.module}/lambda/lambda.zip")

    environment {
      variables = {
        BUCKET_NAME = aws_s3_bucket.aws_s3_resource.bucket
      }
    }
}
```

### 7. API Gateway REST API

Configuración completa del API Gateway con rutas y métodos:

```217:294:main.tf
// Creacion de la API rest utilizando API GATEWAY
resource "aws_api_gateway_rest_api" "aws_api_gateway_resource" {
    name = "aws_api_gateway_resource"
    description = "API para subir y eliminar archivos en S3"
}

// rutas de la API REST
resource "aws_api_gateway_resource" "ruta_upload" {
  rest_api_id = aws_api_gateway_rest_api.aws_api_gateway_resource.id
  parent_id = aws_api_gateway_rest_api.aws_api_gateway_resource.root_resource_id
  path_part = "upload"
}

resource "aws_api_gateway_resource" "ruta_delete" {
    rest_api_id = aws_api_gateway_rest_api.aws_api_gateway_resource.id
    parent_id = aws_api_gateway_rest_api.aws_api_gateway_resource.root_resource_id
    path_part = "delete"
}


// METODOS POST y DELETE
resource "aws_api_gateway_method" "metodo_upload" {
    rest_api_id = aws_api_gateway_rest_api.aws_api_gateway_resource.id
    resource_id = aws_api_gateway_resource.ruta_upload.id
    http_method = "POST"
    authorization = "NONE"
}

resource "aws_api_gateway_method" "metodo_delete" {
    rest_api_id = aws_api_gateway_rest_api.aws_api_gateway_resource.id
    resource_id = aws_api_gateway_resource.ruta_delete.id
    http_method = "DELETE"
    authorization = "NONE"
}

// Integracion del API Gateway con Lambda
resource "aws_api_gateway_integration" "upload_integracion" {
    rest_api_id = aws_api_gateway_rest_api.aws_api_gateway_resource.id
    resource_id = aws_api_gateway_resource.ruta_upload.id
    http_method = aws_api_gateway_method.metodo_upload.http_method

    integration_http_method = "POST"
    type = "AWS_PROXY"
    uri = aws_lambda_function.aws_lambda_resource.invoke_arn
}

resource "aws_api_gateway_integration" "delete_integracion" {
    rest_api_id = aws_api_gateway_rest_api.aws_api_gateway_resource.id
    resource_id = aws_api_gateway_resource.ruta_delete.id
    http_method = aws_api_gateway_method.metodo_delete.http_method

    integration_http_method = "POST"
    type = "AWS_PROXY"
    uri = aws_lambda_function.aws_lambda_resource.invoke_arn
}

// Permitiendo que API Gateway invoque a lambda
resource "aws_lambda_permission" "api_permisos" {
    statement_id  = "AllowExecutionFromAPIGateway"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.aws_lambda_resource.function_name
    principal     = "apigateway.amazonaws.com"
    source_arn = "${aws_api_gateway_rest_api.aws_api_gateway_resource.execution_arn}/*/*"
}

// Despliegue del API Gateway
resource "aws_api_gateway_deployment" "aws_apideploy_resource" {
    depends_on = [
        aws_api_gateway_integration.upload_integracion,
        aws_api_gateway_integration.delete_integracion
    ]
     rest_api_id = aws_api_gateway_rest_api.aws_api_gateway_resource.id
}

resource "aws_api_gateway_stage" "prod_stage" {
    rest_api_id = aws_api_gateway_rest_api.aws_api_gateway_resource.id
    deployment_id = aws_api_gateway_deployment.aws_apideploy_resource.id
    stage_name = "prod"
}
```

### 8. AWS WAF v2

Implementación de reglas WAF para protección del API Gateway:

```301:403:main.tf
resource "aws_wafv2_web_acl" "aws_waf_resource" {
  name = "api-gateway-waf"
  description = "WAF para proteger API Gateway"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  // Creacion de la primer regla --> Rate Limiting
  rule{
    name = "RateLimitRule"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit = 10
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name = "RateLimitRule"
      sampled_requests_enabled = true
    }
  }

  // Creacion de la segunda regla --> Bloque temporal del endpoint DELETE
  rule {
    name = "BlockDeleteWithPattern"
    priority = 2

    action {
      block {
        custom_response {
          response_code = 403
        }
      }
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            search_string = "/delete"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string = "DELETE_BLOCK_TRIGGER"
            field_to_match {
              body {
                oversize_handling = "CONTINUE"
              }
            }
            text_transformation {
              priority = 0
              type = "NONE"
            }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name = "BlockDeleteWithPattern"
      sampled_requests_enabled = true
    }
  }


  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name = "APIGatewayWAF"
    sampled_requests_enabled = true
  }

  tags = {
    Name = "API-Gateway-WAF"
  }
}

// Asociar la web ACL con API Gateway
resource "aws_wafv2_web_acl_association" "api_gateway_waf" {
  resource_arn = aws_api_gateway_stage.prod_stage.arn
  web_acl_arn = aws_wafv2_web_acl.aws_waf_resource.arn
}
```

### 9. AWS Backup

Sistema automatizado de backups para el bucket S3:

```409:472:main.tf
// Backup Vault
resource "aws_backup_vault" "aws_backup_vault_resource" {
  name = "s3-backup-vault"
  kms_key_arn = aws_kms_key.aws_cmk_resource.arn

  tags = {
    Name = "S3-Backup-Vault"
  }
}


// Plan de Backup
resource "aws_backup_plan" "aws_backup_plan_resource" {
  name = "s3-backup-plan"

  rule {
    rule_name         = "daily_backup"
    target_vault_name = aws_backup_vault.aws_backup_vault_resource.name
    schedule          = "cron(0 18 ? * TUE *)"

    lifecycle {
      delete_after = 75
    }
  }

  tags = {
    Name = "S3-Backup-Plan"
  }
}

// Asignacion del bucket de S3 al plan de backup

resource "aws_iam_role" "backup_role" {
  name = "aws-backup-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

// Adjuntar politicas de AWS Backup al rol
resource "aws_iam_role_policy_attachment" "backup_policy" {
  role       = aws_iam_role.backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

// Asignación del bucket S3 al plan de backup
resource "aws_backup_selection" "backup_selection" {
  name         = "s3-backup-selection"
  plan_id      = aws_backup_plan.aws_backup_plan_resource.id
  iam_role_arn = aws_iam_role.backup_role.arn

  resources = [
    aws_s3_bucket.aws_s3_resource.arn
  ]
}
```

### 10. Outputs

Definición de todos los outputs del proyecto:

```1:131:output.tf
# ==============================================
# OUTPUTS DE S3
# ==============================================

output "s3_bucket_name" {
  description = "Nombre del bucket S3"
  value       = aws_s3_bucket.aws_s3_resource.bucket
}

output "s3_bucket_arn" {
  description = "ARN del bucket S3"
  value       = aws_s3_bucket.aws_s3_resource.arn
}

output "s3_bucket_region" {
  description = "Región del bucket S3"
  value       = aws_s3_bucket.aws_s3_resource.region
}

# ==============================================
# OUTPUTS DE KMS
# ==============================================

output "kms_key_id" {
  description = "ID de la llave CMK"
  value       = aws_kms_key.aws_cmk_resource.key_id
}

output "kms_key_arn" {
  description = "ARN de la llave CMK"
  value       = aws_kms_key.aws_cmk_resource.arn
}

# ==============================================
# OUTPUTS DE API GATEWAY
# ==============================================

output "api_gateway_url" {
  description = "URL base del API Gateway"
  value       = aws_api_gateway_stage.prod_stage.invoke_url
}

output "api_upload_endpoint" {
  description = "Endpoint completo para subir archivos"
  value       = "${aws_api_gateway_stage.prod_stage.invoke_url}/upload"
}

output "api_delete_endpoint" {
  description = "Endpoint completo para eliminar archivos"
  value       = "${aws_api_gateway_stage.prod_stage.invoke_url}/delete"
}

output "api_gateway_id" {
  description = "ID del API Gateway"
  value       = aws_api_gateway_rest_api.aws_api_gateway_resource.id
}

# ==============================================
# OUTPUTS DE LAMBDA
# ==============================================

output "lambda_function_name" {
  description = "Nombre de la función Lambda"
  value       = aws_lambda_function.aws_lambda_resource.function_name
}

output "lambda_function_arn" {
  description = "ARN de la función Lambda"
  value       = aws_lambda_function.aws_lambda_resource.arn
}

output "lambda_role_arn" {
  description = "ARN del rol IAM de Lambda"
  value       = aws_iam_role.aws_iamrole_resource.arn
}

# ==============================================
# OUTPUTS DE WAF
# ==============================================

output "waf_web_acl_id" {
  description = "ID del Web ACL de WAF"
  value       = aws_wafv2_web_acl.aws_waf_resource.id
}

output "waf_web_acl_arn" {
  description = "ARN del Web ACL de WAF"
  value       = aws_wafv2_web_acl.aws_waf_resource.arn
}

# ==============================================
# OUTPUTS DE BACKUP
# ==============================================

output "backup_vault_name" {
  description = "Nombre del Backup Vault"
  value       = aws_backup_vault.aws_backup_vault_resource.name
}

output "backup_vault_arn" {
  description = "ARN del Backup Vault"
  value       = aws_backup_vault.aws_backup_vault_resource.arn
}

output "backup_plan_id" {
  description = "ID del plan de backup"
  value       = aws_backup_plan.aws_backup_plan_resource.id
}

output "backup_plan_arn" {
  description = "ARN del plan de backup"
  value       = aws_backup_plan.aws_backup_plan_resource.arn
}

# ==============================================
# OUTPUTS INFORMATIVOS
# ==============================================

output "deployment_summary" {
  description = "Resumen de la infraestructura desplegada"
  value = {
    bucket_name          = aws_s3_bucket.aws_s3_resource.bucket
    api_url              = aws_api_gateway_stage.prod_stage.invoke_url
    lambda_function      = aws_lambda_function.aws_lambda_resource.function_name
    encryption_enabled   = "KMS CMK"
    versioning_enabled   = "Enabled"
    waf_protection       = "Enabled"
    backup_schedule      = "Martes 18:00 UTC"
    mfa_delete_required  = "Enabled"
  }
}
```

## 📁 Estructura del Proyecto

```
.
├── main.tf              # Recursos principales de infraestructura
├── variables.tf         # Variables de configuración
├── providers.tf         # Configuración del proveedor AWS
├── output.tf            # Outputs de la infraestructura
├── lambda/              # Código de la función Lambda
│   └── lambda.zip       # Archivo comprimido de Lambda
└── README.md            # Esta documentación
```

## ⚙️ Configuración

### Requisitos Previos

1. **Terraform**: Versión 1.0 o superior
2. **AWS CLI**: Configurado con credenciales válidas
3. **Permisos AWS**: El usuario/rol debe tener permisos para crear:
   - S3 buckets
   - KMS keys
   - Lambda functions
   - API Gateway
   - WAF
   - AWS Backup
   - IAM roles y políticas

### Variables

El proyecto utiliza una variable de configuración:

| Variable | Descripción | Tipo | Valor por Defecto |
|----------|-------------|------|-------------------|
| `aws_region` | Región de AWS donde se desplegarán los recursos | `string` | `us-west-2` |

Para modificar la región, edita `variables.tf` o usa:

```bash
terraform apply -var="aws_region=us-east-1"
```

### Proveedor

El proyecto utiliza el proveedor oficial de AWS:
- **Source**: `hashicorp/aws`
- **Version**: `~> 6.0`

## 🚀 Despliegue

### Inicialización

```bash
terraform init
```

### Planificación

```bash
terraform plan
```

### Aplicación

```bash
terraform apply
```

Confirma la creación de recursos escribiendo `yes` cuando se solicite.

### Verificación

Después del despliegue, puedes verificar los outputs con:

```bash
terraform output
```

## 📤 Outputs

El proyecto genera los siguientes outputs:

### S3
- `s3_bucket_name`: Nombre del bucket S3
- `s3_bucket_arn`: ARN del bucket S3
- `s3_bucket_region`: Región del bucket S3

### KMS
- `kms_key_id`: ID de la llave CMK
- `kms_key_arn`: ARN de la llave CMK

### API Gateway
- `api_gateway_url`: URL base del API Gateway
- `api_upload_endpoint`: Endpoint completo para subir archivos
- `api_delete_endpoint`: Endpoint completo para eliminar archivos
- `api_gateway_id`: ID del API Gateway

### Lambda
- `lambda_function_name`: Nombre de la función Lambda
- `lambda_function_arn`: ARN de la función Lambda
- `lambda_role_arn`: ARN del rol IAM de Lambda

### WAF
- `waf_web_acl_id`: ID del Web ACL de WAF
- `waf_web_acl_arn`: ARN del Web ACL de WAF

### Backup
- `backup_vault_name`: Nombre del Backup Vault
- `backup_vault_arn`: ARN del Backup Vault
- `backup_plan_id`: ID del plan de backup
- `backup_plan_arn`: ARN del plan de backup

### Resumen
- `deployment_summary`: Resumen completo de la infraestructura desplegada

## 🔒 Características de Seguridad

### 1. Cifrado
- **Cifrado en reposo**: Todos los objetos en S3 están cifrados usando KMS CMK
- **Rotación de claves**: Habilitada automáticamente
- **Gestión de claves**: Clave gestionada por el cliente (CMK)

### 2. Control de Acceso
- **Principio de privilegios mínimos**: Los roles IAM tienen solo los permisos necesarios
- **Política de bucket**: Requiere MFA para eliminar objetos
- **Restricciones de recursos**: Permisos limitados a recursos específicos

### 3. Protección WAF
- **Rate Limiting**: Protección contra ataques de fuerza bruta (10 req/IP)
- **Filtrado de contenido**: Bloqueo de patrones maliciosos en DELETE
- **Monitoreo**: Métricas en CloudWatch para análisis de tráfico

### 4. Versionamiento
- **Historial de versiones**: Todas las versiones de objetos se conservan
- **Recuperación**: Permite restaurar versiones anteriores

### 5. Backups Automatizados
- **Frecuencia**: Backups semanales programados
- **Retención**: 75 días de historial
- **Cifrado**: Backups cifrados con KMS
- **Recuperación ante desastres**: Plan de recuperación implementado

## 📝 Uso de la API

### Subir un archivo

```bash
curl -X POST https://<api-gateway-url>/prod/upload \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "mi-archivo.txt",
    "content": "base64-encoded-content"
  }'
```

### Eliminar un archivo

```bash
curl -X DELETE https://<api-gateway-url>/prod/delete \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "mi-archivo.txt"
  }'
```

**Nota**: Las solicitudes DELETE que contengan el patrón `DELETE_BLOCK_TRIGGER` en el cuerpo serán bloqueadas por WAF.

## 🔄 Historial de Cambios

El proyecto ha evolucionado a través de los siguientes commits principales:

1. **Inicialización**: Configuración inicial de Terraform y proveedor AWS
2. **S3 Bucket**: Creación del bucket S3 en la región de Oregón
3. **Versionamiento**: Habilitación de versionamiento en S3
4. **Política MFA**: Implementación de política que requiere MFA para eliminar objetos
5. **KMS CMK**: Creación de clave CMK para cifrado de S3
6. **Lambda Function**: Implementación de función Lambda con rol IAM seguro
7. **API Gateway**: Desarrollo y despliegue de API REST
8. **WAF**: Implementación de reglas de protección contra ataques
9. **AWS Backup**: Sistema automatizado de backups con retención de 75 días

## 🧹 Limpieza

Para eliminar todos los recursos creados:

```bash
terraform destroy
```

**Advertencia**: 
- La CMK de KMS tiene una ventana de eliminación de 7 días
- Los backups se eliminarán según la política de retención configurada
- Asegúrate de tener backups adicionales si necesitas conservar datos

## 📊 Monitoreo

### CloudWatch Metrics

El WAF genera las siguientes métricas en CloudWatch:
- `RateLimitRule`: Solicitudes bloqueadas por rate limiting
- `BlockDeleteWithPattern`: Solicitudes DELETE bloqueadas por patrón
- `APIGatewayWAF`: Métricas generales del WAF

### Logs de Lambda

Los logs de la función Lambda están disponibles en CloudWatch Logs bajo:
```
/aws/lambda/lambda_api_code
```

## 🛠️ Mantenimiento

### Actualización de Lambda

1. Actualiza el código en `lambda/`
2. Regenera `lambda.zip`
3. Ejecuta `terraform apply`

Terraform detectará cambios mediante `source_code_hash`.

### Modificación de Reglas WAF

Edita las reglas en `main.tf` bajo el recurso `aws_wafv2_web_acl` y ejecuta `terraform apply`.

### Ajuste de Backups

Modifica el cron schedule en `aws_backup_plan`:
- Actual: `cron(0 18 ? * TUE *)` (Martes 18:00 UTC)
- Formato: `cron(minuto hora día mes día-semana)`

## 📚 Referencias

- [Documentación de Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [AWS WAF Documentation](https://docs.aws.amazon.com/waf/)
- [AWS Backup Documentation](https://docs.aws.amazon.com/aws-backup/)

## 👤 Autor

**Luispmv** - luispmv07@hotmail.com

## 📄 Licencia

Este proyecto es parte de un trabajo académico de seguridad en la nube.

---

**Última actualización**: Diciembre 2025

