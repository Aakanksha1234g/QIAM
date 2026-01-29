---
## 🔹 Method 1: Install Keycloak (official distribution – recommended)

### 1️⃣ Install Java (Keycloak 22+ needs Java 17+)

```bash
java -version
```

If not installed:

**Ubuntu / Debian**

```bash
sudo apt update
sudo apt install openjdk-17-jdk -y
```

**RHEL / CentOS / Rocky / Alma**

```bash
sudo dnf install java-17-openjdk -y
```

Verify:

```bash
java -version
```
---
### 2️⃣ Download Keycloak

```bash
cd /opt
sudo wget https://github.com/keycloak/keycloak/releases/download/26.0.0/keycloak-26.0.0.tar.gz
```

Extract:

```bash
sudo tar -xvzf keycloak-26.0.0.tar.gz
sudo mv keycloak-26.0.0 keycloak
```

(Optional permissions)

```bash
sudo chown -R $USER:$USER /opt/keycloak
```

---

### 3️⃣ Create Admin User

```bash
cd /opt/keycloak
bin/kc.sh bootstrap-admin user
```

You’ll be prompted for:

* **username**
* **password**

---

### 4️⃣ Start Keycloak (Dev Mode)

```bash
bin/kc.sh start-dev
```

---

### 5️⃣ Access Keycloak

Open browser:

```
http://localhost:8080
```

Admin console:

```
http://localhost:8080/admin
```

Login with the admin credentials you created.

---

## 🔹 Method 2: Run Keycloak using Docker (fastest)

```bash
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.0.0 \
  start-dev
```

Access:

```
http://localhost:8080
```

---

## 🔹 Method 3: Production Setup (Quick Overview)

For prod, you’ll typically:

* Use **PostgreSQL / MySQL**
* Enable HTTPS
* Run optimized mode

Example:

```bash
bin/kc.sh build
bin/kc.sh start \
  --db=postgres \
  --db-url=jdbc:postgresql://localhost/keycloak \
  --db-username=keycloak \
  --db-password=secret
```

(We can deep-dive into this when you want)

---

## 🔹 Common Commands You’ll Use A LOT

```bash
bin/kc.sh start-dev        # dev mode
bin/kc.sh start            # prod mode
bin/kc.sh stop
bin/kc.sh show-config
```

---



After **Step 1 (Java install)** you can absolutely  **connect Keycloak to a PostgreSQL (psql) database** .
In fact, for long-term use, **you SHOULD do this** 👍

Below are **clean, correct steps** (no shortcuts).

---

# 🔗 Connect Keycloak 26.0.0 with PostgreSQL

## 🔹 Prerequisites

You already have:

* ✅ Java 17 installed
* ✅ Keycloak extracted in `/opt/keycloak`

---

## 🔹 STEP 1: Install PostgreSQL

### Ubuntu / Debian

```bash
sudo apt install postgresql postgresql-contrib -y
```

### RHEL / Rocky / Alma

```bash
sudo dnf install postgresql-server postgresql-contrib -y
sudo postgresql-setup --initdb
```

Start & enable:

```bash
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

Check:

```bash
sudo systemctl status postgresql
```

---

## 🔹 STEP 2: Create DB and User for Keycloak

Switch to postgres user:

```bash
sudo -i -u postgres
```

Open psql:

```bash
psql
```

Run:

```sql
CREATE DATABASE keycloak;
CREATE USER keycloak WITH PASSWORD 'StrongPassword123';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
\q
```

Exit:

```bash
exit
```

---

## 🔹 STEP 3: Configure Keycloak to use PostgreSQL

Go to Keycloak:

```bash
cd /opt/keycloak
```

### Export DB config (recommended way)

```bash
export KC_DB=postgres
export KC_DB_URL=jdbc:postgresql://localhost:5432/keycloak
export KC_DB_USERNAME=keycloak
export KC_DB_PASSWORD=StrongPassword123
```

---

## 🔹 STEP 4: Build Keycloak (IMPORTANT)

This step  **locks DB config into Keycloak** .

```bash
bin/kc.sh build
```

---

## 🔹 STEP 5: Create Admin User (if not done already)

```bash
bin/kc.sh bootstrap-admin user
```

---

## 🔹 STEP 6: Start Keycloak (Production mode)

```bash
bin/kc.sh start
```

⚠️ Notice: **NOT `start-dev`**

---

## 🔹 STEP 7: Verify PostgreSQL is being used

Check logs — you should see:

```
Using PostgreSQL database
```

Or verify in psql:

```bash
sudo -u postgres psql keycloak
\dt
```

You’ll see tables like:

```
realm
user_entity
client
```

🎉 That confirms Keycloak is using PostgreSQL.

---

## 🧠 Why this is the RIGHT time to do it

* No data migration later
* Clean production setup
* Stable for long-term use
* Required for clustering & scaling

---

## ⚠️ Very important notes

* ❌ Do NOT use H2 for long-term
* ❌ Do NOT switch DB after users exist
* ✅ Always backup DB before upgrades

---

## 🔜 What I recommend next

Now that you’re on PostgreSQL, next logical steps:

1. Create your **first realm**
2. Decide **single-realm vs multi-realm**
3. Create **clients (confidential/public)**
4. Design **roles vs groups**
5. Token mappers (claims)

If you want, tell me:

* single app or multi-tenant?
* Node.js / Java / Python backend?
* Docker later or bare-metal only?

I’ll guide you like a real production setup 👌
