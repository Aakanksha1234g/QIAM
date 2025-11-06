from utils.configuration import KEYCLOAK_REALM,KEYCLOAK_SERVER_URL,ADMIN_CLIENT_ID,ADMIN_CLIENT_SECRET
from utils.configuration import APP_CLIENT_ID,APP_CLIENT_SECRET,APP_HOME_URL,APP_REDIRECT_URL
import requests

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
