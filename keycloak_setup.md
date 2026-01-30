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

1. These credentials are admin credentials.
1. In **Keycloak UI**, in masters **realm** under **Users** tab a user will be created with these credentials.
1. Never delete this user. If this user is deleted then UI will show sign in error and again from terminal it would be necessary to create admin user.
1. To create admin user:
   * ```bash
     export KC_BOOTSTRAP_ADMIN_USERNAME=admin
     echo $KC_BOOTSTRAP_ADMIN_USERNAME
     export KC_BOOTSTRAP_ADMIN_PASSWORD=admin@123
     ```

5. Start the server:

```bash
./bin/kc.sh start-dev
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
http://<pc-ip>:8081
```

1. Sign in with admin username and password.
2. After sign in Keycloak's realm : master (default realm) would be created.

#### Connect Keycloak 26.0.0 with Postgresql

###### Install Postgresql 

```bash
sudo apt update
sudo apt install postgresql postgresql-contrib -y
```

###### Start and enable Postgresql

```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

###### Create Keycloak DB + user

```bash
sudo -u postgres psql -c "CREATE DATABASE keycloak;"
sudo -u postgres psql -c "CREATE USER keycloak WITH PASSWORD 'StrongPass123!';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;"
```

###### Download PostgreSQL JDBC driver

```bash
cd ~/Projects/QIAM/keyclk/keycloak-api-client/keycloak-26.4.1
mkdir -p providers
cd providers
wget https://jdbc.postgresql.org/download/postgresql-42.7.4.jar
```

###### Configure Keycloak for PostgreSQL

```bash
cat >> ~/Projects/QIAM/keyclk/keycloak-api-client/keycloak-26.4.1/conf/keycloak.conf << EOF
db=postgres
db-url=jdbc:postgresql://localhost:5432/keycloak
db-username=keycloak
db-password=keycloak@123
EOF
```

###### Stop Keycloak if running

```bash
sudo systemctl stop keycloak 2>/dev/null || pkill -f keycloak
```

###### Export env variables

```bash
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD=admin@123
```

Provide the credentials used at the time of creating the admin user.

###### Start Keycloak with PostgreSQL (first time setup)

```bash
./bin/kc.sh start-dev
```
