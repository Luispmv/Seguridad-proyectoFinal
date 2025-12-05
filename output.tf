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