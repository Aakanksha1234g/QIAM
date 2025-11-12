Below is a **complete, production-ready recipe** for **using Keycloak for authentication + your PostgreSQL RBAC tables for fine-grained authorization** in a school-attendance app.

---

## 1. High-Level Architecture

```
[Browser / Mobile] → Keycloak (OpenID Connect) → Your App (Spring / Node / Go …)
                              ↓
                     PostgreSQL (users + RBAC tables)
```

| Piece                     | Responsibility                                                                                                                              |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **Keycloak**        | *Authentication* (login, MFA, password reset, SSO) + **coarse roles** (optional)                                                    |
| **PostgreSQL RBAC** | *Authorization* – decide **exactly** what a logged-in user can do (`mark_attendance`, `view_own_attendance`, …)               |
| **Your App**        | After Keycloak validates the ID/Access token → look up user in `users` table → load permission list from RBAC tables → enforce in code |

---

## 2. Step-by-Step Integration

### 2.1 Create a Realm in Keycloak

1. Admin Console → **Create Realm** → `school-attendance`
2. **Clients** → **Create Client**
   - Client ID: `attendance-app`
   - Client Protocol: `openid-connect`
   - Access Type: **confidential** (or public if SPA)
   - Valid Redirect URIs: `https://yourapp.com/oidc/callback`
   - Enable **Standard Flow**, **Direct Access Grants** (optional)

> **Tip**: Keep *“Implicit Flow”* **off**; use Authorization Code Flow (PKCE for SPA).

---

### 2.2 Sync Users from PostgreSQL → Keycloak (One-Time or Ongoing)

You **don’t** want two user tables. Pick **one source of truth**.

#### Option A – **Keycloak is the source of truth** (recommended for IAM)

- Users are created **in Keycloak** (Admin Console, Registration, SCIM, or API).
- Your app **creates a matching row** in PostgreSQL `users` table **on first login**.

#### Option B – **PostgreSQL is the source of truth** (if you already have 10 000 students)

- Use **Keycloak User Storage SPI** (custom provider) **or** nightly sync script.

**Simple sync script (Python example)**

```python
import psycopg2, requests, json

KC_URL = "https://keycloak.example.com"
REALM  = "school-attendance"
TOKEN  = get_admin_token()   # client credentials

conn = psycopg2.connect(dsn)
cur = conn.cursor()
cur.execute("SELECT id, email, full_name FROM users WHERE kc_id IS NULL")

for uid, email, name in cur:
    payload = {
        "username": email,
        "email": email,
        "firstName": name.split()[0],
        "lastName": " ".join(name.split()[1:]),
        "enabled": True,
        "credentials": [{"type":"password","value":"Temp123!","temporary":True}]
    }
    r = requests.post(f"{KC_URL}/admin/realms/{REALM}/users",
                      headers={"Authorization": f"Bearer {TOKEN}"},
                      json=payload)
    if r.status_code == 201:
        kc_id = r.headers['Location'].split('/')[-1]
        cur.execute("UPDATE users SET kc_id = %s WHERE id = %s", (kc_id, uid))
conn.commit()
```

---

### 2.3 Add `kc_id` Column to Your `users` Table

```sql
ALTER TABLE users ADD COLUMN kc_id UUID UNIQUE;
-- Index for fast lookup
CREATE INDEX idx_users_kc_id ON users(kc_id);
```

---

### 2.4 First-Login Hook in Your App (Any Framework)

**Goal**: When Keycloak redirects back with a valid token → find/create PostgreSQL user → load RBAC permissions.

#### Example (Spring Boot + Spring Security)

```java
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           JwtDecoder jwtDecoder,
                                           UserSyncService syncService) throws Exception {
        http
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/admin/**").hasAuthority("manage_users")
                .requestMatchers("/api/attendance/mark").hasAuthority("mark_attendance")
                .anyRequest().authenticated()
            )
            .addFilterBefore(new FirstLoginFilter(syncService), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

**FirstLoginFilter**

```java
public class FirstLoginFilter extends OncePerRequestFilter {
    private final UserSyncService sync;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        Jwt jwt = (Jwt) req.getAttribute("jwt"); // set by Spring
        String sub = jwt.getSubject(); // Keycloak user UUID

        User user = userRepo.findByKcId(UUID.fromString(sub))
                           .orElseGet(() -> sync.createUserFromJwt(jwt));
        SecurityContextHolder.getContext().setAuthentication(
            new JwtAuthenticationToken(jwt, user.getAuthorities()));
        chain.doFilter(req, res);
    }
}
```

**UserSyncService**

```java
@Transactional
public User createUserFromJwt(Jwt jwt) {
    String email = jwt.getClaimAsString("email");
    String name  = jwt.getClaimAsString("name");

    User u = new User();
    u.setKcId(UUID.fromString(jwt.getSubject()));
    u.setEmail(email);
    u.setFullName(name);
    u.setUsername(email);
    u.setStatus("active");
    userRepo.save(u);

    // Assign default role (e.g., student)
    roleRepo.findByName("student").ifPresent(role -> {
        userRoleRepo.save(new UserRole(u, role));
    });
    return u;
}
```

---

### 2.5 Load RBAC Permissions → Spring Authorities

```java
@Entity
public class User {
    // ...
    @Transient
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissionRepo.findPermissionsByUserId(this.id).stream()
                .map(p -> new SimpleGrantedAuthority(p.getCode()))
                .collect(Collectors.toList());
    }
}
```

**SQL View (recommended for speed)**

```sql
CREATE VIEW user_permissions AS
SELECT DISTINCT u.id AS user_id, p.code
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN role_permissions rp ON rp.role_id = ur.role_id
JOIN permissions p ON p.id = rp.permission_id;
```

Then query:

```java
@Query(value = "SELECT code FROM user_permissions WHERE user_id = :userId", nativeQuery = true)
List<String> findPermissionCodesByUserId(@Param("userId") Long userId);
```

---

## 3. Authorization Enforcement (Example Endpoints)

```java
@RestController
@RequestMapping("/api/attendance")
@PreAuthorize("hasAuthority('mark_attendance')")
public class AttendanceController {

    @PostMapping("/mark")
    public Response mark(@RequestBody MarkDto dto,
                         @AuthenticationPrincipal Jwt jwt) {
        Long userId = userRepo.findByKcId(UUID.fromString(jwt.getSubject())).get().getId();
        // additional business logic: only allow marking own class, etc.
    }
}
```

---

## 4. Optional: Push Coarse Roles from Keycloak (Hybrid)

If you want **some** roles in Keycloak (e.g., `admin`, `teacher`) **and** fine-grained permissions in DB:

1. In Keycloak → **Client Scopes** → Create `roles` mapper:

   - Name: `role-mapper`
   - Mapper Type: **User Realm Role**
   - Token Claim Name: `roles`
   - Add to ID/Access token: **ON**
2. In your app, read `jwt.getClaim("roles")` → auto-assign DB role if missing.

---

## 5. Full SQL Schema (PostgreSQL)

```sql
-- 1. Users (with Keycloak link)
CREATE TABLE users (
    id         BIGSERIAL PRIMARY KEY,
    kc_id      UUID UNIQUE,
    username   VARCHAR(100) UNIQUE NOT NULL,
    email      VARCHAR(255) UNIQUE NOT NULL,
    full_name  VARCHAR(200),
    status     VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. RBAC tables (same as before)
CREATE TABLE roles (...);
CREATE TABLE permissions (...);
CREATE TABLE user_roles (...);
CREATE TABLE role_permissions (...);

-- 3. Fast permission view
CREATE VIEW user_permissions AS
SELECT u.id AS user_id, p.code
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN role_permissions rp ON rp.role_id = ur.role_id
JOIN permissions p ON p.id = rp.permission_id;

CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_role_perm_role ON role_permissions(role_id);
```

---

## 6. Testing the Flow

1. **Login** via Keycloak → get Access Token.
2. Call your API with `Authorization: Bearer <token>`.
3. App:
   - Validates token (Keycloak JWKS).
   - Extracts `sub` → finds/creates `users` row.
   - Loads permissions via view.
   - `@PreAuthorize` blocks unauthorized calls.

---

## 7. Security Best Practices

| Item                                                             | Why                                                   |
| ---------------------------------------------------------------- | ----------------------------------------------------- |
| **HTTPS everywhere**                                       | Tokens in transit                                     |
| **Short-lived access tokens** (5–15 min) + refresh tokens | Reduce exposure                                       |
| **Rotate client secrets**                                  | Confidential clients                                  |
| **Store only `kc_id` in DB**                             | Never store Keycloak password                         |
| **Rate-limit login**                                       | Prevent brute-force                                   |
| **Audit log**                                              | Add `audit_log` table for every `mark_attendance` |

---

## 8. TL;DR Checklist

| Done | Task                                                  |
| ---- | ----------------------------------------------------- |
| 1    | Create Keycloak realm + OIDC client                   |
| 2    | Add `kc_id UUID` to `users` table                 |
| 3    | On first login: create PostgreSQL user from JWT       |
| 4    | Load permissions via `user_permissions` view        |
| 5    | Enforce with `@PreAuthorize("hasAuthority('...')")` |
| 6    | (Optional) Sync coarse roles from Keycloak            |

---

**You now have:**

- **Keycloak** → rock-solid login, MFA, SSO
- **PostgreSQL RBAC** → fine-grained school-specific permissions
- **One source of truth** (choose Keycloak or DB)
- **Zero code duplication**

Drop this into Spring, Node (Passport), Go (go-oidc), or any framework — the pattern is identical. Let me know which stack you’re using and I’ll give you the exact code snippet!
