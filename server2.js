const express = require('express');
const Redis = require('redis');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));

// Redis connection
const redis = Redis.createClient({ url: 'redis://localhost:6379' });
redis.connect().catch(console.error);

// Rate limiting
const limiter = rateLimit({ windowMs: 60 * 1000, max: 10000 });
app.use('/auth', limiter);

// 🔐 FIXED: Get these from Keycloak Admin Console → Clients → LorvenAI-app → Credentials
const config = {
  KEYCLOAK_URL: 'http://localhost:8081',
  KEYCLOAK_REALM: 'LorvenAI-realm',
  CLIENT_ID: 'LorvenAI-app',
  CLIENT_SECRET: 'YOUR_ACTUAL_CLIENT_SECRET_HERE', // ← CHANGE THIS
  JWT_SECRET: 'your-super-secret-jwt-key-change-in-prod',
  ADMIN_TOKEN: 'YOUR_KEYCLOAK_ADMIN_TOKEN' // Get via /realms/master/protocol/openid-connect/token
};

// MAIN LOGIN - PERFECT AS-IS ✅
app.post('/auth/login', limiter, async (req, res) => {
  try {
    const { user_email, user_password } = req.body;
    
    const tokens = await axios.post(
      `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'password',
        client_id: config.CLIENT_ID,
        client_secret: config.CLIENT_SECRET,
        username: user_email,
        password: user_password,
        scope: 'openid email profile'
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const userId = tokens.data.sub;
    const cacheKey = `perms:${userId}`;

    let permissions = await redis.get(cacheKey);
    if (!permissions) {
      const userInfo = await axios.get(
        `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/userinfo`,
        { headers: { Authorization: `Bearer ${tokens.data.access_token}` } }
      );
      
      permissions = mapRolesToScreens(userInfo.data.realm_access?.roles || []);
      await redis.setEx(cacheKey, 900, JSON.stringify(permissions));
    } else {
      permissions = JSON.parse(permissions);
    }

    const enrichedToken = jwt.sign({
      sub: userId,
      permissions,
      modules: Object.keys(permissions)
    }, config.JWT_SECRET, { expiresIn: '15m' });

    res.json({
      data: {
        response: {
          access_token: enrichedToken,
          refresh_token: tokens.data.refresh_token,
          permissions,
          modules: Object.keys(permissions)
        }
      }
    });

  } catch (error) {
    console.error('Login failed:', error.response?.data || error.message);
    res.status(401).json({ data: { detail: 'Invalid credentials' } });
  }
});

// ✅ NEW: Complete Signup Implementation
app.post('/auth/signup', limiter, async (req, res) => {
  try {
    const { user_email, user_password, firstName, lastName } = req.body;

    // Step 1: Create user in Keycloak
    const createUser = await axios.post(
      `${config.KEYCLOAK_URL}/admin/realms/${config.KEYCLOAK_REALM}/users`,
      {
        username: user_email,
        email: user_email,
        enabled: true,
        emailVerified: true,
        firstName,
        lastName,
        credentials: [{
          type: 'password',
          value: user_password,
          temporary: false
        }],
        realmRoles: ['user'] // Default role - customize in Keycloak
      },
      {
        headers: {
          'Authorization': `Bearer ${config.ADMIN_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (createUser.status === 201) {
      // Step 2: Auto-login new user
      const loginTokens = await axios.post(
        `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token`,
        new URLSearchParams({
          grant_type: 'password',
          client_id: config.CLIENT_ID,
          client_secret: config.CLIENT_SECRET,
          username: user_email,
          password: user_password,
          scope: 'openid email profile'
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      const userId = loginTokens.data.sub;
      const permissions = mapRolesToScreens(['user']); // Default user permissions
      const enrichedToken = jwt.sign({
        sub: userId,
        permissions,
        modules: Object.keys(permissions)
      }, config.JWT_SECRET, { expiresIn: '15m' });

      res.json({
        data: {
          response: {
            access_token: enrichedToken,
            refresh_token: loginTokens.data.refresh_token,
            permissions,
            modules: Object.keys(permissions),
            message: 'Account created successfully'
          }
        }
      });
    }
  } catch (error) {
    console.error('Signup failed:', error.response?.data || error.message);
    res.status(400).json({ 
      data: { detail: error.response?.data?.errorMessage || 'Signup failed' } 
    });
  }
});

// ✅ NEW: Token refresh endpoint
app.post('/auth/refresh', async (req, res) => {
  try {
    const { refresh_token } = req.body;
    const tokens = await axios.post(
      `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: config.CLIENT_ID,
        client_secret: config.CLIENT_SECRET,
        refresh_token
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    res.json({
      data: {
        response: {
          access_token: tokens.data.access_token,
          refresh_token: tokens.data.refresh_token
        }
      }
    });
  } catch (error) {
    res.status(401).json({ data: { detail: 'Invalid refresh token' } });
  }
});

// PERFECT UTILITY FUNCTION ✅
function mapRolesToScreens(roles) {
  const permissions = {};
  roles?.forEach(role => {
    if (role.includes('.')) {
      const [module, screen, operation] = role.split('.');
      if (['cinescribe', 'cinesketch', 'cineflow', 'pitchcraft'].includes(module)) {
        permissions[module] = permissions[module] || {};
        permissions[module][screen] = permissions[module][screen] || [];
        if (!permissions[module][screen].includes(operation)) {
          permissions[module][screen].push(operation);
        }
      }
    }
  });
  return permissions;
}

app.listen(3001, () => {
  console.log('🚀 Auth Middleware running on http://localhost:3001');
  console.log('✅ Frontend (5173) → Middleware (3001) → Keycloak (8081)');
});
