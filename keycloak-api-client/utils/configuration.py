from pydantic import BaseModel

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