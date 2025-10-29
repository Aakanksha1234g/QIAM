
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import requests

app = FastAPI()

# Keycloak Configuration
KEYCLOAK_SERVER_URL = "http://localhost:8080"      #keycloak webpage
KEYCLOAK_REALM = "demo"                           # realm in which fastapi_admin and fastapi_app clients are created 

# Dedicated Admin Client for FastAPI application's internal Keycloak management
ADMIN_CLIENT_ID = "fastapi-admin-client" # Choose a unique ID for your admin client
ADMIN_CLIENT_SECRET = "88SzGccWOBAAxR2Pzad5K3DQpUZJP0if" # GENERATE A STRONG SECRET

# Client for your application (e.g., to register users via API)
APP_CLIENT_ID = "fastapi-app-client"
APP_CLIENT_SECRET = "YpmSb1YJqavHiHDQL8dBZPdij9JSvp2z" # in credentials tab of fastapi-app client

# OAuth2PasswordBearer for dependency injection
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserRegister(BaseModel):
    username: str
    password: str
    email: str
    firstName: str
    lastName: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenRefresh(BaseModel):
    refreshToken: str

class TokenIntrospect(BaseModel):
    accessToken: str

def get_admin_access_token():
    print("Inside get_admin_access_token function...")
    token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    payload = {
        "client_id": ADMIN_CLIENT_ID,
        "client_secret": ADMIN_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }

    try:
        print("posting request to keycloak with token url and payload")
        response = requests.post(token_url, data=payload)
        print("response got from keycloak is:",response)
        response.raise_for_status()
        print("Admin access token successfully obtained.") # Added for debugging
        print("Admin token is:", response.json()["access_token"])
        return response.json()["access_token"]
    except requests.exceptions.RequestException as e:
        print(f"Error obtaining admin access token with admin client: {e}")
        return None

async def configure_app_client():
    print("Getting access token...")
    admin_access_token = get_admin_access_token()
    if not admin_access_token:
        print("Failed to configure app client: Could not obtain admin access token")
        return

    clients_url = f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients"
    headers = {"Authorization": f"Bearer {admin_access_token}", "Content-Type": "application/json"}

    try:
        # Check if fastapi-app client already exists
        response = requests.get(f"{clients_url}?clientId={APP_CLIENT_ID}", headers=headers)
        response.raise_for_status()
        existing_clients = response.json()

        client_id_in_keycloak = None
        if existing_clients:
            print("APP_CLIENT already exists...")
            client_id_in_keycloak = existing_clients[0]["id"]
            print("client_id_in_keycloak:",client_id_in_keycloak)

        app_client_config = {               #fastapi client behaviour definition
            "clientId": APP_CLIENT_ID,       #client name
            "enabled": True,                 # active client and can be used for authentication
            "protocol": "openid-connect",       #uses OpenID Connect(OIDC) protocol for authentication and authorization
            "publicClient": False,              # confidential client
            "secret": APP_CLIENT_SECRET,       #client secret
            "directAccessGrantsEnabled": True,   #allows to send username and password to keycloak's token endpoint, without redirecting to login page
            "serviceAccountsEnabled": True,      #enable service account to manage users, create users 
            "redirectUris": ["*"], # Allow all redirect URIs for flexibility in this example
        }

        if client_id_in_keycloak:
            print(f"Updating existing client {APP_CLIENT_ID}...")
            update_url = f"{clients_url}/{client_id_in_keycloak}"
            response = requests.put(update_url, headers=headers, json=app_client_config)
            response.raise_for_status()
            print(f"Client {APP_CLIENT_ID} updated successfully.")
        else:
            print(f"Creating new client {APP_CLIENT_ID}...")
            response = requests.post(clients_url, headers=headers, json=app_client_config)
            response.raise_for_status()
            print(f"Client {APP_CLIENT_ID} created successfully.")
            response = requests.get(f"{clients_url}?clientId={APP_CLIENT_ID}", headers=headers)
            response.raise_for_status()
            client_id_in_keycloak = response.json()[0]["id"]

        # Assign service account roles to 'fastapi-app' client
        if client_id_in_keycloak:
            print(f"Configuring service account roles for client {APP_CLIENT_ID}...")
            service_account_user_url = f"{clients_url}/{client_id_in_keycloak}/service-account-user"
            response = requests.get(service_account_user_url, headers=headers)
            response.raise_for_status()
            service_account_user_id = response.json()["id"]

            response = requests.get(f"{clients_url}?clientId=realm-management", headers=headers)
            response.raise_for_status()
            realm_management_client_id = response.json()[0]["id"]

            roles_url = f"{clients_url}/{realm_management_client_id}/roles"
            response = requests.get(roles_url, headers=headers)
            response.raise_for_status()
            available_roles = response.json()

            roles_to_assign = [
                role for role in available_roles
                if role["name"] in ["manage-users", "query-users"]
            ]
            
            if roles_to_assign:
                assign_roles_url = f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users/{service_account_user_id}/role-mappings/clients/{realm_management_client_id}"
                response = requests.post(assign_roles_url, headers=headers, json=roles_to_assign)
                response.raise_for_status()
                print("Service account roles assigned successfully for fastapi-app.")
            else:
                print("Required roles (manage-users, query-users) not found in realm-management client for fastapi-app.")


    except requests.exceptions.RequestException as e:
        print(f"Error configuring app client: {e}")

@app.on_event("startup")
async def startup_event():
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
        "firstName": user.firstName,
        "lastName": user.lastName,
        "credentials": [{
            "type": "password",
            "value": user.password,
            "temporary": False
        }]
    }
    try:
        response = requests.post(users_url, headers=headers, json=user_data)
        response.raise_for_status()
        print(f"Username {user.username} registered successfully")
        return {"message": "User registered successfully"}
    except requests.exceptions.RequestException as e:
        print(f"Error registering user: {e}")
        if response.status_code == 409:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User with this username or email already exists")
        raise HTTPException(status_code=response.status_code if hasattr(response, 'status_code') else status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to register user: {e}")

@app.post("/login")
async def login_for_access_token(user: UserLogin):
    token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    payload = {
        "client_id": APP_CLIENT_ID,           #fast-api
        "client_secret": APP_CLIENT_SECRET,    #from credentials app
        "username": user.username,      #admin
        "password": user.password,      #admin@123
        "grant_type": "password"
    }
    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        print(f"User {user.username} logged in successfully")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error during user login: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or user login failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/logout")
async def logout_user(token_refresh: TokenRefresh):
    logout_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
    payload = {
        "client_id": APP_CLIENT_ID,
        "client_secret": APP_CLIENT_SECRET,
        "refresh_token": token_refresh.refreshToken
    }
    try:
        response = requests.post(logout_url, data=payload)
        response.raise_for_status()
        return {"message": "Logged out successfully"}
    except requests.exceptions.RequestException as e:
        print(f"Error during user logout: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Logout failed")

@app.post("/introspect")
async def introspect_token_endpoint(token_introspect: TokenIntrospect):
    introspection_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"
    payload = {
        "client_id": APP_CLIENT_ID,
        "client_secret": APP_CLIENT_SECRET,
        "token": token_introspect.accessToken
    }
    try:
        response = requests.post(introspection_url, data=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error during token introspection: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token introspection failed")

@app.get("/")
async def root():
    return {"message": "Keycloak API Client (FastAPI) is running!"}
