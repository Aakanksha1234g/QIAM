from fastapi import HTTPException
from admin_token import get_admin_access_token
import requests
from utils.configuration import KEYCLOAK_REALM,KEYCLOAK_SERVER_URL

def check_user(username:str):
    admin_token = get_admin_access_token()
    if not admin_token:
        raise HTTPException(status_code=500, detail="Could not obtain admin token")
    url = f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users"
    headers = {"Authorization":f"Bearer {admin_token}"}
    # parameters:
    # username, exact :- exact match no partial matches, max :- 1  
    params = {"username":username,"exact":"true","max":1}  
    response = requests.get(url, headers=headers,params=params)
    response.raise_for_status()
    users = response.json()
    if users:
        return users[0]
    else:
        return None
