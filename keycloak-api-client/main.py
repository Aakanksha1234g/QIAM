from typing import Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
import requests
from datetime import datetime
import datetime as dateTime
from logged_in_user import login_details, set_logged_in_user_details
from users import check_user
from utils.configuration import KEYCLOAK_REALM,KEYCLOAK_SERVER_URL,APP_CLIENT_ID,APP_CLIENT_SECRET,APP_HOME_URL,APP_REDIRECT_URL
from utils.configuration import UserLogin,TokenIntrospect,UserRegister
from admin_token import get_admin_access_token,configure_app_client

app = FastAPI()

#Fix browser block(CORS) from redirecting
app.add_middleware( 
    CORSMiddleware,
    allow_origins=["http://192.168.29.136:8000"],       #at production this will change with the applications URL
    allow_credentials = True,
    allow_methods=["*"],
    allow_headers = ["*"],
    )

#token_state of access token
token_state = None

@app.on_event("startup")
async def startup_event():
    print("FASTAPI application starting... Configuring Kecyloak client...")
    await configure_app_client()

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user_endpoint(user: UserRegister):
    print("Inside register endpoint...Getting admin_access_token")
    admin_access_token = get_admin_access_token()
    print("Admin access token is:",admin_access_token)
    if not admin_access_token:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not obtain admin access token")

    users_url = f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users"
    headers = {"Authorization": f"Bearer {admin_access_token}", "Content-Type": "application/json"}
    user_data = {
        "username": user.username,
        "enabled": True,
        "email": user.email,
        "emailVerified":True,
    }
    try:
        response = requests.post(users_url, headers=headers, json=user_data)
        response.raise_for_status()
        print(f"Username {user.username} registered successfully")
        return {"message": f"User {user.username} registered successfully"}
    except requests.exceptions.RequestException as e:
        print(f"Error registering user {user.username}: {e}")
        if response.status_code == 409:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User with this username or email already exists")
        raise HTTPException(status_code=response.status_code if hasattr(response, 'status_code') else status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to register user {user.username}: {e}")

@app.post("/introspect")
async def introspect_token_endpoint(token_introspect: TokenIntrospect):
    global token_state
    introspection_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"
    payload = {
        "client_id": APP_CLIENT_ID,
        "client_secret": APP_CLIENT_SECRET,
        "token": token_introspect.accessToken
    }
    try:
        now = datetime.now()
        response = requests.post(introspection_url, data=payload)
        print(f"Introspect request has been sent at {now.strftime("%H:%M:%S")}")
        response.raise_for_status()
        print(f"response is : {response.json()}")
        result = response.json()
        token_state = result.get("active")
        print("token state is:",token_state)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error during token introspection: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token introspection failed")

@app.get("/")
async def root():
    return {"message": "Keycloak API Client (FastAPI) is running!"}

@app.get("/logged_in_user_details")
async def user_info():
    print("token state is:",token_state)
    print("logged in details are:",login_details(token_state))
    return {"message":login_details(token_state)}

#To get the user info in FastAPI Swagger
@app.post("/login")
async def login_for_access_token(user:UserLogin):
    print("Login endpoint has been called...")
    print(f"Checking if user {user.username} exists in Keycloak...")
    userExists = check_user(user.username)
    if not userExists:
        print(f"User {user.username} doesn't exist. Register the user.")
        raise HTTPException(status_code=500, detail="User doesn't exist in Keycloak.Register the user.")
    print(f"User {user.username} exists in Keycloak") 
    token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"   #OpenID Connect Protocol
    # admin_token = get_admin_access_token()
    param = {
        "client_id":APP_CLIENT_ID,
        "client_secret":APP_CLIENT_SECRET,   #Required if confidential
        "grant_type":'client_credentials',    # using OAuth 2.0 to get access token for client
        "scope":"openid email profile"      #OpenID Connect to get identity information.
    }
    try:
        response = requests.post(token_url,data=param)
        response.raise_for_status()
        if response.status_code!=200:
            raise HTTPException(status_code=400,detail="Invalid credentials")
        tokens = response.json()
        access_token_expiry = dateTime.timedelta(seconds=tokens['expires_in'])
        refresh_token_expiry = dateTime.timedelta(seconds=tokens['refresh_expires_in'])
        now = datetime.now()
        print(f"User {user.username} logged in at {now.strftime("%H:%M:%S")}")
        print(f"Access token for user {user.username} is given at expires in {access_token_expiry} minutes")
        print(f"Refresh token for user {user.username} expires in {refresh_token_expiry} minutes")
        set_logged_in_user_details(user.username,user.email)
        return tokens
    except requests.exceptions.RequestException as e:
        print(f"Error while user login : {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="User login failed")

@app.post("/revoke-token")       
async def revoke_token(token: Optional[str]=None):
    """Revoke access or refresh token using Keycloak's revocation endpoint
    Provide access/refresh token or Authorization bearer token(access/refresh token) """
    print("Token:",token)
    revoke_token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/revoke"
    payload = {
        "client_id":APP_CLIENT_ID,
        "client_secret":APP_CLIENT_SECRET,
        "token":token
    }
    try:
        response = requests.post(revoke_token_url,data=payload)
        response.raise_for_status()
        return {"message":"Token revoked."}
    except requests.exceptions.RequestException as e:
        print(f"Error revoking token: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to revoke token:{e}")

