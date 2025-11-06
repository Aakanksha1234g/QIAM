from typing import Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import requests
import requests
from datetime import datetime
import datetime as dateTime
from logged_in_user import login_details, set_logged_in_user_details

app = FastAPI()

#Fix browser block(CORS) from redirecting
app.add_middleware( 
    CORSMiddleware,
    allow_origins=["http://192.168.29.136:8000"],       #at production this will change with the applications URL
    allow_credentials = True,
    allow_methods=["*"],
    allow_headers = ["*"],
    )

# Keycloak Configuration
KEYCLOAK_SERVER_URL = "http://localhost:8080"      #keycloak webpage
KEYCLOAK_REALM = "demo"                           # realm in which fastapi_admin and fastapi_app clients are created 

# Dedicated Admin Client for FastAPI application's internal Keycloak management
ADMIN_CLIENT_ID = "fastapi-admin-client" # Choose a unique ID for your admin client
ADMIN_CLIENT_SECRET = "88SzGccWOBAAxR2Pzad5K3DQpUZJP0if" # GENERATE A STRONG SECRET

# Client for your application (e.g., to register users via API)
APP_CLIENT_ID = "fastapi-app-client"
APP_CLIENT_SECRET = "YpmSb1YJqavHiHDQL8dBZPdij9JSvp2z" # in credentials tab of fastapi-app client

#Application URL to redirect after login
APP_REDIRECT_URL = "http://localhost:8000/"
APP_HOME_URL = "http://localhost:8000"

# OAuth2PasswordBearer for dependency injection
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#token_state of access token
token_state = None

class UserRegister(BaseModel):
    username: str
    email: str

class UserLogin(BaseModel):
    username: str
    email : str

class UserLogout(BaseModel):
    # refreshToken: str
    accessToken : str

class TokenIntrospect(BaseModel):
    accessToken: str

def get_admin_access_token():
    print("Inside get_admin_access_token function...")
    #token_ril is used to get access token for admin client
    token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    payload = {
        "client_id": ADMIN_CLIENT_ID,
        "client_secret": ADMIN_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }

    try:
        # print("posting request to keycloak with token url and payload")
        response = requests.post(token_url, data=payload)
        # print("response got from keycloak is:",response)
        response.raise_for_status()                    #checks for response status, if response status is 200 then program continues othewise raises exception that request has failed                
        # print("Admin access token successfully obtained.")       
        # print("Admin token is:", response.json()["access_token"])
        return response.json()["access_token"]
    except requests.exceptions.RequestException as e:
        print(f"Error obtaining admin access token with admin client: {e}")
        return None

async def configure_app_client():
    # print("Getting access token...")
    admin_access_token = get_admin_access_token()
    if not admin_access_token:
        # print("Failed to configure app client: Could not obtain admin access token")
        return

    clients_url = f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients"
    headers = {"Authorization": f"Bearer {admin_access_token}", "Content-Type": "application/json"}

    try:
        # Check if fastapi-app client already exists
        # print("Sending request to keycloak and checking if app client exists")
        response = requests.get(f"{clients_url}?clientId={APP_CLIENT_ID}", headers=headers)
        response.raise_for_status()
        existing_clients = response.json()
        # print("status of app client is ",existing_clients)

        client_id_in_keycloak = None
        if existing_clients:
            # print("APP_CLIENT already exists...")
            client_id_in_keycloak = existing_clients[0]["id"]
            # print("client_id_in_keycloak:",client_id_in_keycloak)

        # print("app client behaviour")
        app_client_config = {               #fastapi client behaviour definition
            "clientId": APP_CLIENT_ID,       #client name
            "enabled": True,                 # active client and can be used for authentication
            "protocol": "openid-connect",       #uses OpenID Connect(OIDC) protocol for authentication and authorization
            "publicClient": False,              # confidential client
            "secret": APP_CLIENT_SECRET,       #client secret
            "directAccessGrantsEnabled": True,   #allows to send username and password to keycloak's token endpoint, without redirecting to login page
            "serviceAccountsEnabled": True,      #enable service account to manage users, create users 
            "redirectUris": [
                APP_HOME_URL, APP_REDIRECT_URL,
                "http://127.0.0.1:8000/*", "http://127.0.0.1:8000",
                "http://localhost:8000/callback"
            ], 
            "weborigins":["http://localhost:8000", "http://127.0.0.1:8000"],
            "attributes":{ 
                "oauth.device.authorization.grant.enabled":"false",
                "oidc.ciba.grant.enabled":"false",
                "post.logout.redirect.uris":"http://localhost:8000"
            }
        }

        if client_id_in_keycloak:
            # print(f" App client already exists. Updating it {APP_CLIENT_ID}...")
            update_url = f"{clients_url}/{client_id_in_keycloak}"
            response = requests.put(update_url, headers=headers, json=app_client_config)
            response.raise_for_status()
            # print(f"Client {APP_CLIENT_ID} updated successfully.")
        else:
            # print(f"Creating new app client {APP_CLIENT_ID}...")
            response = requests.post(clients_url, headers=headers, json=app_client_config)
            response.raise_for_status()
            # print(f"Client {APP_CLIENT_ID} created successfully.")
            response = requests.get(f"{clients_url}?clientId={APP_CLIENT_ID}", headers=headers)
            response.raise_for_status()
            client_id_in_keycloak = response.json()[0]["id"]

        # Assign service account roles to 'fastapi-app' client
        if client_id_in_keycloak:
            # print(f"Assigning service account roles for client {APP_CLIENT_ID}...")
            service_account_user_url = f"{clients_url}/{client_id_in_keycloak}/service-account-user"
            # print("Sending request to keycloak with app client details and header")
            response = requests.get(service_account_user_url, headers=headers)
            response.raise_for_status()
            # print("Service account user id for app client is:",response.json()["id"])
            service_account_user_id = response.json()["id"]
            # print("Sending request to keycloak for realm-management roles")
            response = requests.get(f"{clients_url}?clientId=realm-management", headers=headers)
            response.raise_for_status()
            realm_management_client_id = response.json()[0]["id"]
            # print("realm_management_client_id is:",realm_management_client_id)
            roles_url = f"{clients_url}/{realm_management_client_id}/roles"
            # print("Sending request to keycloak to get the avaialable roles for the app client...")
            response = requests.get(roles_url, headers=headers)
            response.raise_for_status()
            available_roles = response.json()
            # print("Available roles for app client:",available_roles)
            roles_to_assign = [
                role for role in available_roles
                if role["name"] in ["manage-users", "query-users"]
            ]
            if roles_to_assign:
                assign_roles_url = f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users/{service_account_user_id}/role-mappings/clients/{realm_management_client_id}"
                response = requests.post(assign_roles_url, headers=headers, json=roles_to_assign)
                response.raise_for_status()
                # print("Service account roles assigned successfully for fastapi-app.")
            else:
                print("Required roles (manage-users, query-users) not found in realm-management client for fastapi-app.")
    except requests.exceptions.RequestException as e:
        print(f"Error configuring app client: {e}")

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
    token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    # admin_token = get_admin_access_token()
    param = {
        "client_id":APP_CLIENT_ID,
        "client_secret":APP_CLIENT_SECRET,   #Required if confidential
        "grant_type":'client_credentials',
        "scope":"openid email profile"
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

# #For redirection to application
# @app.get("/login")
# async def login_for_access_token():
#     print("/login endpoint has been called..")
#     #General state for CSRF protection
#     state = secrets.token_urlsafe(32)
#     #Build authorization url
#     auth_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
#     params = {
#         "client_id":APP_CLIENT_ID,
#         "redirect_uri":f"{APP_HOME_URL}",
#         "response_type":"code",
#         "scope":"openid email profile",
#         "state":state
#     }
#     query_string = urlencode(params)
#     print("query is:",query_string)
#     redirect_url = f"{auth_url}?{query_string}"
#     print(f"Redirecting to Keycloak's login page:{redirect_url}")
#     return RedirectResponse(url=redirect_url)

# @app.get("/callback")
# async def callback(code:str, state:str=None):
#     print("/callback endpoint has been called...")
#     """Handles the callback from Keycloak after user logs in """
#     print(f"Received authorization code:{code}")
#     #Exchange authorization code for tokens
#     token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
#     payload = {
#         "client_id":APP_CLIENT_ID,
#         "client_secret":APP_CLIENT_SECRET,
#         "code":code,
#         "grant_type":"authorization_code",
#         "redirect_uri":f"{APP_HOME_URL}/callback"
#     }
#     try:
#         response = requests.post(token_url,data=payload)
#         response.raise_for_status()
#         tokens = response.json()
#         access_token = tokens.get('access_token','')
#         print(f"access token :{access_token}")
        
#         #to get username and email
#         payload_part = access_token.split('.')[1]
#         print(f"payload part:{payload_part}")
#         decoded_payload = base64.urlsafe_b64decode(payload_part)
#         print(f"decoded payload:{decoded_payload}")
#         user_info = json.loads(decoded_payload)
#         print(f"user info:{user_info}")
        
#         #Printing user info
#         print(f"Username : {user_info.get('preferred_username','N/A')}")
#         print(f"Email : {user_info.get('email','N/A')}")
#         print(f"Access token expires in :{tokens.get('expires_in',0)/60} minutes")

#         #Redirect to home page with token
#         return RedirectResponse(url=f"{APP_HOME_URL}/?token={tokens['access_token']}")
    
#     except requests.exceptions.RequestException as e:
#         print(f"Token exchange failed: {e}")
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Authentication failed")

# @app.post("/logout")
# async def logout_user(token:UserLogout):
#     #Logout user and revoke refresh token
#     #Checking username from refresh token, app_client_id and app_client_secret
#     url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/introspect"
#     payload = {
#         "client_id":APP_CLIENT_ID,
#         "client_secret":APP_CLIENT_SECRET,
#         "token":token.accessToken,
#     }
#     username = None
#     try:
#         response = requests.post(url,data=payload)
#         if response.status_code == 200:
#             token_info = response.json()
#             if token_info.get("active"):   
#                 username = token_info.get("preferred_username") or token_info.get("username")
#                 print(f"User {username} is logging out...")
#     except Exception as e:
#         print(f"Warning: Could not introspect token before logout:{e}")

#     #Logging out
#     logout_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
#     payload = {
#         "client_id": APP_CLIENT_ID,
#         "client_secret": APP_CLIENT_SECRET,
#         "refresh_token": token.accessToken
#     }
#     try:
#         response = requests.post(logout_url, data=payload)
#         response.raise_for_status()
#         print(f"User {username} logged out successfully")
#         return {"message": f"User {username} logged out successfully"}
#     except requests.exceptions.RequestException as e:
#         print(f"Error during user logout: {e}")
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Logout failed")

# @app.post("/refresh")
# async def refresh_token_endpoint(refresh:TokenRefresh):
#     print("/refresh endpoint has been called...")
#     token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
#     param = {
#         "client_id":APP_CLIENT_ID,
#         "client_secret":APP_CLIENT_SECRET,
#         "grant_type":"refresh_token",
#         "refresh_token":refresh.refreshToken
#     }
#     try:
#         response = requests.post(token_url,data=param)
#         response.raise_for_status()
#         tokens = response.json()
#         access_token = tokens.get("access_token")
#         refresh_token = tokens.get("refresh_token")
#         access_token_expiry = dateTime.timedelta(seconds=tokens["expires_in"])
#         refresh_token_expiry = dateTime.timedelta(seconds=tokens["refresh_expires_in"])
#         now = datetime.now()

#         print(f"New tokens have been assigned at:{now.strftime("%H:%M:%S")}")
#         print(f"New access token expires in : {access_token_expiry} minutes")
#         print(f"New refresh token expires in : {refresh_token_expiry} minutes")

#         return {
#             "access_token":access_token,
#             "token_type":"bearer",
#             "expires_in":tokens["expires_in"],
#             "refresh_token":refresh_token,
#             "refresh_expires_in":tokens["refresh_expires_in"],
#             "access_token_expires_different_format":str(access_token_expiry),
#             "refresh_token_expired_different_format":str(refresh_token_expiry)
#         }
#     except requests.exceptions.HTTPError as e:
#         print(f"Refresh token failed:{e}")
#         raise HTTPException(status_code=400,detail="Invalid refresh token")
#     except requests.exceptions.RequestException as e:
#         print(f"Refresh token failed with request exception:{e}")
#         raise HTTPException(status_code=500, detail="Internal server error")

