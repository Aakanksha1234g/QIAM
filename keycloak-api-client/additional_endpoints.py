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

