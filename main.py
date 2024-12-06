import json
import uvicorn

from typing import Union
from fastapi import FastAPI, HTTPException, Response, Request
from utils.database import fetch_query_as_json
from utils.security import validate, validate_func

from fastapi.middleware.cors import CORSMiddleware
from models.UserRegister import UserRegister
from models.UserLogin import UserLogin
from models.EmailActivation import EmailActivation
from models.codeActivation import CodeRequest

from controllers.firebase import verify_activation_code, register_user_firebase, login_user_firebase, generate_activation_code

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permitir todos los orígenes
    allow_credentials=True,
    allow_methods=["*"],  # Permitir todos los métodos
    allow_headers=["*"],  # Permitir todos los encabezados
)

@app.get("/")
async def read_root(response: Response):
    response.headers["Cache-Control"] = "no-cache"
    query = "SELECT [FirstName], [LastName], [Email], [Active] FROM [dbo_test].[USERS]"
    try:
        result = await fetch_query_as_json(query)
        result_dict = json.loads(result)
        result_dict = {
            "data": result_dict
            , "version": "0.0.4"
        }
        return result_dict
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/register")
async def register(user: UserRegister):
    return  await register_user_firebase(user)

@app.post("/login")
async def login_custom(user: UserLogin):
    return await login_user_firebase(user)

@app.get("/user")
@validate
async def user(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-cache"
    return {
        "email": request.state.email
        , "firstname": request.state.firstname
        , "lastname": request.state.lastname
    }

@app.post("/user/{email}/code")
@validate_func
async def generate_code(request: Request, email: str):
    e = EmailActivation(email=email)
    return await generate_activation_code(e)

@app.post("/user/{email}/code/{code}")
async def activate_account(request: Request, code: str, email: str):
    e = EmailActivation(email=email)
    c = CodeRequest(code=code)
    return await verify_activation_code(e, c)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)