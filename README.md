Note:-

1. Using Postgresql database in this project as it will work under following conditions:
   1. High traffic
   2. Concurrent access
   3. Zero tolerance for corruption.
   4. Need reliable backups.
2. Fastapi backend server is used so no Java/Javascript adapter is used.
   1. Thus following are the settings done:
      1. Root URL : URL where the application is running.
         1. E.g. http://localhost:2000
      2. Valid redirect URL : URL where the user will be redirected after logging in keycloak /logging out from keycloak.
         1. E.g. http://localhost:2000/callback
      3.
