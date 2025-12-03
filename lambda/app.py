import json
import boto3
import base64
import os

s3 = boto3.client("s3")
BUCKET_NAME = os.environ.get("BUCKET_NAME")

def respond(status, message):
    return {
        "statusCode": status,
        "body": json.dumps({"message": message})
    }


# def handler(event, context):
#     try:
#         action = event.get("action")

#         if action == "put":
#             return upload_file(event)
#         elif action == "delete":
#             return delete_file(event)
#         else:
#             return respond(400, "Acción inválida. Usa 'put' o 'delete'.")

#     except Exception as e:
#         return respond(500, f"Error interno: {str(e)}")

def handler(event, context):
    try:
        # API Gateway manda el JSON en event["body"]
        if "body" in event:
            event = json.loads(event["body"])

        action = event.get("action")

        if action == "put":
            return upload_file(event)
        elif action == "delete":
            return delete_file(event)
        else:
            return respond(400, "Acción inválida. Usa 'put' o 'delete'.")

    except Exception as e:
        return respond(500, f"Error interno: {str(e)}")



# -----------------------------
# SUBIR ARCHIVO A S3 (PutObject)
# -----------------------------
def upload_file(event):
    try:
        key = event["key"]                       # nombre del archivo en S3
        file_content_base64 = event["content"]   # contenido en Base64

        file_bytes = base64.b64decode(file_content_base64)

        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=key,
            Body=file_bytes
        )

        return respond(200, f"Archivo '{key}' subido correctamente.")

    except KeyError:
        return respond(400, "Faltan campos obligatorios: key, content.")
    except Exception as e:
        return respond(500, f"Error subiendo archivo: {str(e)}")


# --------------------------------
# ELIMINAR ARCHIVO DE S3 (DeleteObject)
# --------------------------------
def delete_file(event):
    try:
        key = event["key"]

        s3.delete_object(
            Bucket=BUCKET_NAME,
            Key=key
        )

        return respond(200, f"Archivo '{key}' eliminado correctamente.")

    except KeyError:
        return respond(400, "Falta el campo obligatorio: key.")
    except Exception as e:
        return respond(500, f"Error eliminando archivo: {str(e)}")
