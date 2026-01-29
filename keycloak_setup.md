### Steps to install Keycloak

#### Install Java (Keycloak runs on JVM)

```bash
sudo apt update
sudo apt install openjdk-17-jdk -y
java -version
```

#### Download Keycloak

```bash
mkdir Projects
cd Projects 
sudo wget https://github.com/keycloak/keycloak/releases/download/26.0.0/keycloak-26.4.1.tar.gz
sudo tar -xvzf keycloak-26.4.1.tar.gz
sudo mv keycloak-26.4.1 keycloak
sudo chown -R $USER:$USER /Projects/keycloak
```

#### Create Admin User

```bash
cd /Projects/keycloak
bin/kc.sh bootstrap-admin user
```

Provide details in prompt: 

* username
* password

Note :

* These credentials are admin credentials.
* In **Keycloak UI**, in masters **realm** under **Users** tab a user will be created with these credentials.
* Never delete this user. If this user is deleted then UI will show sign in error and again from terminal it would be necessary to create admin user.
* To create admin user:
  * ```bash

    ```

#### Start Keycloak

```bash
cd /Projects/keycloak
./bin/kc.sh start-dev
```

By default keycloak runs on port 8080

To run keycloak on different port, e.g. port 8081

```bash
./bin/kc.sh start-dev --http-port=8081
```

#### Access Keycloak

```bash
http://localhost:8081
```

1. Sign in with admin username and password.
2. After sign in Keycloak's realm : master (default realm) would be created.

#### Connect Keycloak 26.0.0 with Postgresql
