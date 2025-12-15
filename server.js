const express = require('express');           // Creates web server to handle HTTP requests
const Redis = require('redis');               // Fast in-memory cache for storing permissions
const jwt = require('jsonwebtoken');          // Creates/validates secure tokens
const axios = require('axios');               // Makes HTTP requests to Keycloak
const cookieParser = require('cookie-parser'); // Reads cookies from browser requests
const cors = require('cors');                 // Allows frontend (5173) to talk to backend (3001)
const rateLimit = require('express-rate-limit'); // Prevents spam attacks (10k req/min max)

const app = express(); // Creates our main web server

// ================= MIDDLEWARE (runs on EVERY request) =================
// Parses incoming JSON data from frontend (like {email, password})
app.use(express.json());

// Reads cookies sent by browser (like auth_token)
app.use(cookieParser());

// Allows requests from React frontend running on localhost:5173
app.use(cors({
  origin: 'http://localhost:5173',  // Only allow YOUR frontend
  credentials: true                 // Allow cookies to be sent
}));

// ================= REDIS CONNECTION (permissions cache) =================
// Redis stores user permissions so we don't ask Keycloak every time
const redis = Redis.createClient({ 
  url: 'redis://localhost:6379'     // Redis server address
});
redis.connect(); // Connect to Redis (runs in background)

// ================= RATE LIMITING (security) =================
// Limits users to 10k login attempts per minute to prevent spam/bots
const limiter = rateLimit({ 
  windowMs: 60 * 1000,              // 1 minute window
  max: 10000                        // Max 10k requests per minute per IP
});
app.use('/auth', limiter);             // Only apply to /auth routes

// ================= CONFIGURATION (Keycloak settings) =================
const config = {
  KEYCLOAK_URL: 'http://localhost:8081',      // Your Keycloak server
  KEYCLOAK_REALM: 'LorvenAI-realm',           // Your Keycloak database/realm
  CLIENT_ID: 'LorvenAI-app',                  // Your app registered in Keycloak
  CLIENT_SECRET: 'your-secret',               // Secret from Keycloak client settings
  JWT_SECRET: 'your-super-secret-jwt-key'     // Secret for our custom tokens
};

// ================= MAIN LOGIN ENDPOINT =================
app.post('/auth/login', limiter, async (req, res) => {
  try {
    // Extract email/password from frontend request
    const { user_email, user_password } = req.body;
    
    // STEP 1: Ask Keycloak to verify credentials (like asking a bouncer)
    const tokens = await axios.post(
      `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token`,
      new URLSearchParams({                    // Keycloak expects form data format
        grant_type: 'password',                // We're using password login
        client_id: config.CLIENT_ID,
        client_secret: config.CLIENT_SECRET,
        username: user_email,
        password: user_password,
        scope: 'openid email profile'          // Get user info too
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    // STEP 2: Get unique user ID from Keycloak token
    const userId = tokens.data.sub;            // Keycloak user ID (like user123)
    const cacheKey = `perms:${userId}`;        // Redis key: "perms:user123"

    // STEP 3: Check Redis cache for user permissions (SUPER FAST)
    let permissions = await redis.get(cacheKey);
    if (!permissions) {
      // Cache MISS: Ask Keycloak for user roles/permissions (slower)
      const userInfo = await axios.get(
        `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/userinfo`,
        { headers: { Authorization: `Bearer ${tokens.data.access_token}` } }
      );
      
      // Convert Keycloak roles to screen permissions
      // Example: "cinescribe.screen1.view" → {cinescribe: {screen1: ["view"]}}
      permissions = mapRolesToScreens(userInfo.data.realm_access?.roles || []);
      
      // Cache for 15 minutes (900 seconds) - next login will be instant!
      await redis.setEx(cacheKey, 900, JSON.stringify(permissions));
    } else {
      // Cache HIT: Super fast (1ms vs 100ms)
      permissions = JSON.parse(permissions);
    }

    // STEP 4: Create SUPER TOKEN with permissions embedded
    const enrichedToken = jwt.sign({
      sub: userId,                           // User ID
      permissions,                           // All screen permissions
      modules: Object.keys(permissions)      // ["cinescribe", "cineflow"]
    }, config.JWT_SECRET, { expiresIn: '15m' }); // Token expires in 15 min

    // STEP 5: Send response in format your frontend expects
    res.json({
      data: {                                // Matches your FastAPI response structure
        response: {
          access_token: enrichedToken,       // Frontend stores this in cookie
          refresh_token: tokens.data.refresh_token, // For token refresh
          permissions,                       // NEW: Screen access rules
          modules: Object.keys(permissions)  // NEW: Which modules to show
        }
      }
    });

  } catch (error) {
    // Login failed (wrong password, etc.)
    console.error('Login failed:', error.response?.data || error.message);
    res.status(401).json({ data: { detail: 'Invalid credentials' } });
  }
});

// ================= SIGNUP ENDPOINT (placeholder) =================
app.post('/auth/signup', limiter, async (req, res) => {
  // TODO: Add your Keycloak user creation logic here
  // Similar to login but creates new user first
  res.json({ 
    data: { 
      response: { 
        success: true,
        access_token: 'signup-token',
        permissions: {},
        modules: []
      } 
    } 
  });
});

// ================= START SERVER =================
app.listen(3001, () => {
  console.log('🚀 Auth Middleware running on http://localhost:3001');
  console.log('✅ Frontend (5173) → Middleware (3001) → Keycloak (8081)');
});

// ================= UTILITY FUNCTION =================
function mapRolesToScreens(roles) {
  /*
  Converts Keycloak roles like:
  ["cinescribe.screen1.view", "cinescribe.screen1.create", "cineflow.screen2.view"]
  
  Into screen permissions:
  {
    cinescribe: {
      screen1: ["view", "create"]
    },
    cineflow: {
      screen2: ["view"]
    }
  }
  */
  const permissions = {};
  roles?.forEach(role => {
    if (role.includes('.')) {              // Skip roles without "module.screen.operation"
      const [module, screen, operation] = role.split('.');
      // Only allow your 4 modules
      if (['cinescribe', 'cinesketch', 'cineflow', 'pitchcraft'].includes(module)) {
        permissions[module] = permissions[module] || {};
        permissions[module][screen] = permissions[module][screen] || [];
        permissions[module][screen].push(operation);
      }
    }
  });
  return permissions;
}
