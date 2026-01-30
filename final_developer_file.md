1. /realms/{realm-name}/protocol/openid-connect/certs

   1. It is used for Json Web Key Set(JWKS) which has realm public keys.
   2. It is used to verify any Json Web Token.
2. JWKS - Json web key set is  a list of public keys which keycloak used to sign the token
3. SMTP - simple mail transfer protocol used for sending emails between servers.
4. Nodemail transporter - is a fixed smtp client that knows

   1. host - connect to this server
   2. port - use this port
   3. auth - sender's email and password.

### Password grant response of token endpoint:

[](https://github.com/Aakanksha1234g/Middleware/blob/main/concepts.md#password-grant-response-of-token-endpoint)

```
{
"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
"expires_in":300,
"refresh_expires_in":1800,
"refresh_token":"...",
"token_type":"Bearer",
"not-before-policy":0,
"session_state":"...",
"scope":"email profile"
}
```

*At brevo->smtp & api
I added new sender with
From Name : Lorvenai
From Email : [aakanksha@thequantum.ai](mailto:aakanksha@thequantum.ai)*

*Your SMTP Settings
SMTP Server : smtp-relay.brevo.com
Port : 587
Login : [9e546b001@smtp-brevo.com](mailto:9e546b001@smtp-brevo.com)*

*I added the fields in keycloak email tab
from : [aakanksha@thequantum.ai](mailto:aakanksha@thequantum.ai)
host : smtp-relay.brevo.com
port : 587
encryption : ✔enabled ssl
authentication : enabled
username : [9e546b001@smtp-brevo.com](mailto:9e546b001@smtp-brevo.com)
authentication type : ✔ password
password : bskKrlIu5XeM93j
allow utf-8 : ✔ enabled*

## Keycloak Realm (LorvenAI) Email tab

[](https://github.com/Aakanksha1234g/Middleware/blob/main/concepts.md#keycloak-realm-lorvenai-email-tab)

In your realm’s **Email** settings:

1. Keep:
   * From: `aakanksha@thequantum.ai                    // this is just for the display`
   * Host: `smtp-relay.brevo.com`
   * Port: `587`
   * Authentication: ON
   * Username: `9e546b001@smtp-brevo.com`
   * Authentication type: `password`
   * Password: `bskKrlIu5XeM93j` (SMTP key)
2. **Change Encryption:**
   * Disable  **SSL** .
   * Enable **StartTLS** (sometimes labelled just “TLS” in Keycloak UI).
     The SSLException `Unsupported or unrecognized SSL message` is exactly what you get when you use SSL on a STARTTLS port.[](https://www.keycloak.org/docs/latest/server_admin/index.html)

* Optionally disable **Allow UTF‑8** (not required for this).
* Click **Test connection** on the Email tab.

## **Organization Admin Roles:**

[](https://github.com/Aakanksha1234g/Middleware/blob/main/concepts.md#organization-admin-roles)

* **`query-groups`** - List groups
* **`query-users`** - Search users
* **`manage-users`** - Create/invite users to their org group
* **`view-users`** - View group members
