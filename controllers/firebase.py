import os
import requests
import json
import logging
import traceback
import random

from datetime import datetime

from dotenv import load_dotenv
from fastapi import HTTPException

from models.UserRegister import UserRegister
from models.UserLogin import UserLogin
from models.EmailActivation import EmailActivation
from models.codeActivation import CodeRequest

import firebase_admin
from firebase_admin import credentials, auth as firebase_auth

from utils.database import fetch_query_as_json
from utils.security import create_jwt_token

from azure.storage.queue import QueueClient, BinaryBase64DecodePolicy, BinaryBase64EncodePolicy

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Inicializar la app de Firebase Admin
cred = credentials.Certificate("secrets/autenticacion-firebase-adminsdk.json")
firebase_admin.initialize_app(cred)

load_dotenv()

azure_sak = os.getenv('AZURE_SAK') #Traer el connection string del storage acount
queue_name = os.getenv('QUEUE_ACTIVATE') #Traer el nombre de la cola

queue_client = QueueClient.from_connection_string(azure_sak, queue_name) #Crear el cliente del queue storage
queue_client.message_decode_policy = BinaryBase64DecodePolicy() #Inicializar el decode policy
queue_client.message_encode_policy = BinaryBase64EncodePolicy() #Inicializar el encode policy

#Esta funcion se encarga de hacer la insercion de los mensajes
async def insert_message_on_queue(message: str):
    message_bytes = message.encode('utf-8') #Codificar el mensaje
    #Enviar el mensaje a la cola    
    queue_client.send_message(
        queue_client.message_encode_policy.encode(message_bytes)
    )
    print("Enviado a la cola")

# Metodo para generar el registro en firebase y en la base de datos
async def register_user_firebase(user: UserRegister):
    user_record = {}
    try:
        # Crear usuario en Firebase Authentication
        user_record = firebase_auth.create_user(
            email=user.email,
            password=user.password
        )

    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=400,
            detail=f"Error al registrar usuario: {e}"
        )

    # Crear el usuario en la base de datos de Azure SQL
    query = f"INSERT INTO dbo_test.USERS (FirstName, LastName, Email) VALUES ('{user.firstname}', '{user.lastname}', '{user.email}');"
    result = {}
    try:

        result_json = await fetch_query_as_json(query)
        print(result_json)
        result = json.loads(result_json)[0]

        await insert_message_on_queue(user.email)

        return result

    except Exception as e:
        firebase_auth.delete_user(user_record.uid)
        raise HTTPException(status_code=500, detail=str(e))

# Metodo para cuando un usuario quiera loguearse
async def login_user_firebase(user: UserLogin):
    try:
        # Autenticar usuario con Firebase Authentication usando la API REST
        api_key = os.getenv("FIREBASE_API_KEY")  # Reemplaza esto con tu apiKey de Firebase
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        payload = {
            "email": user.email,
            "password": user.password,
            "returnSecureToken": True
        }
        response = requests.post(url, json=payload)
        response_data = response.json()

        if "error" in response_data:
            raise HTTPException(
                status_code=400,
                detail=f"Error al autenticar usuario: {response_data['error']['message']}"
            )

        query = f"SELECT [FirstName], [LastName], [Email], [Active], CONVERT(NVARCHAR, [Activate_at], 120) AS Activate_at FROM [dbo_test].[USERS] WHERE [Email] = '{ user.email }'"

        try:
            result_json = await fetch_query_as_json(query)
            result_dict = json.loads(result_json)

            # Verifica si el resultado está vacío (usuario no encontrado)
            if not result_dict:
                raise HTTPException(status_code=404, detail="Usuario no encontrado")

            # Verifica si el usuario está activo
            user_data = result_dict[0]
            if not user_data["Active"]:  # Si 'Active' es False
                # El usuario no está activo, se ejecuta la inserción en la cola
                await insert_message_on_queue(user.email)
            
            return {
                "message": "Usuario autenticado exitosamente",
                "idToken": create_jwt_token(
                    result_dict[0]["FirstName"],
                    result_dict[0]["LastName"],
                    user.email,
                    result_dict[0]["Active"]
                ),
                "userData": result_dict[0]
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        error_detail = {
            "type": type(e).__name__,
            "message": str(e),
            "traceback": traceback.format_exc()
        }
        raise HTTPException(
            status_code=400,
            detail=f"Error al login usuario: {error_detail}"
        )

# Metodo para generar el codigo de activacion
async def generate_activation_code(email: EmailActivation):

    # Generar el codigo
    code = random.randint(100000, 999999)
    query = f"INSERT INTO dbo_test.ACTIVATION_CODES (Email, Code) VALUES ('{email.email}', {code})"
    result = {}
    try:
        result_json = await fetch_query_as_json(query)
        result = json.loads(result_json)[0]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "message": "Código de activación generado exitosamente",
        "code": code
    }

async def verify_activation_code(email: EmailActivation, code: CodeRequest):
    query = f"SELECT TOP 1 [dbo_test].[ACTIVATION_CODES].[Id] FROM [dbo_test].[ACTIVATION_CODES] INNER JOIN [dbo_test].[USERS] ON [dbo_test].[USERS].[Email] = [dbo_test].[ACTIVATION_CODES].[Email] WHERE [dbo_test].[ACTIVATION_CODES].[Code] = '{code.code}' AND [dbo_test].[ACTIVATION_CODES].[Email] = '{email.email}' ORDER BY [dbo_test].[ACTIVATION_CODES].[Created_at] DESC;"
    
    try:
        result_json = await fetch_query_as_json(query)
        results = json.loads(result_json)

        if not results:
            return {}
        
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime('%Y-%m-%d %H:%M:%S')
        
        query2 = f"UPDATE [dbo_test].[USERS] SET [Active] = 1, [Activate_at] = '{formatted_datetime}' WHERE [Email] = '{email.email}';"
        result_json_update = await fetch_query_as_json(query2)

        if result_json_update == "0":
            raise HTTPException(status_code=404, detail="No se pudo hacer la activacion")

        return results[0]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))