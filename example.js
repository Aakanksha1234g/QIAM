// Middleware to verify admin authorization
const verifyAdminToken = async (req, res, next) => {
  try {
    console.log('Verifying admin token...');
    const adminToken = await getAdminToken();
    const { access_token } = req.body;
    
    if (!access_token) {
      return res.status(401).json({ message: "Access token is required" });
    }
    
    console.log('access token:', access_token);
    
    const payload = {
      'client_id': config.ADMIN_CLIENT_ID,
      'client_secret': config.ADMIN_CLIENT_SECRET,
      'token': access_token
    };
    
    const tokenIntrospectResponse = await axios.post(
      `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token/introspect`,
      payload,
      {
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    console.log('tokenIntrospectResponse data:', tokenIntrospectResponse.data);
    
    if (tokenIntrospectResponse.data.active === false) {
      return res.status(401).json({ message: "Admin User Unauthorized" });
    }
    
    // Store the token data in req for use in route handlers
    req.tokenData = tokenIntrospectResponse.data;
    req.resourceAccess = tokenIntrospectResponse.data.resource_access;
    
    next(); // Continue to the next middleware/route handler
  } catch (error) {
    console.error(`Error in verifyAdminToken: ${error.response?.status}, ${error.response?.statusText}`);
    return res.status(error.response?.status || 500).json({
      message: `Authorization failed: ${error.response?.status || 'Unknown error'}, ${error.response?.statusText || error.message}`
    });
  }
};

// Keep the endpoint for direct authorization checks
app.post('/authorizeAdmin', limiter, async (req, res) => {
  try {
    console.log('/authorizeAdmin called...');
    const adminToken = await getAdminToken();
    const { access_token } = req.body;
    console.log('access token:', access_token);
    
    const payload = {
      'client_id': config.ADMIN_CLIENT_ID,
      'client_secret': config.ADMIN_CLIENT_SECRET,
      'token': access_token
    };
    
    const tokenIntrospectResponse = await axios.post(
      `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token/introspect`,
      payload,
      {
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    console.log('tokenIntrospectResponse data:', tokenIntrospectResponse.data);
    
    if (tokenIntrospectResponse.data.active === false) {
      return res.status(401).json({ message: "Admin User Unauthorized" });
    }
    
    return res.status(200).json({
      message: "Admin User Authorized",
      data: tokenIntrospectResponse.data.resource_access
    });
  } catch (error) {
    console.error(`Error in authorizeUser: ${error.response?.status}, ${error.response?.statusText}`);
    res.status(error.response?.status || 500).json({
      message: `authorizeUser unsuccessful: ${error.response?.status}, ${error.response?.statusText}`
    });
  }
});

// Use the middleware in your route
app.post('/modifyUserGroup', limiter, verifyAdminToken, async (req, res) => {
  try {
    const { username, groupName, subGroupName, access_token } = req.body;
    
    // You can access the token data if needed
    // const resourceAccess = req.resourceAccess;
    
    const userExists = await checkUserExists(username); // Fixed: was user_email
    if (!userExists) {
      console.log("User does not exist");
      return res.status(200).json({ message: `User ${username} does not exist` }); // Fixed: res.json(200) -> res.status(200)
    }
    
    const subGroupExists = await checkSubGroupExists(groupName, subGroupName);
    if (!subGroupExists) {
      return res.status(200).json({ message: `Sub group ${subGroupName} doesn't exist.` });
    }
    
    const userExistsInSubGroupResponse = await checkUserExistsInSubGroup(username, groupName, subGroupName); // Fixed: was user_email
    console.log('userExistsInSubGroupResponse:', userExistsInSubGroupResponse);
    
    if (userExistsInSubGroupResponse) {
      return res.status(200).json({ message: `User ${username} already exists in subGroup ${subGroupName}` }); // Fixed: was user_email
    }
    
    const addUserToSubGroupResponse = await addUserToSubGroup(username, groupName, subGroupName); // Fixed: was user_email
    console.log('addUserToSubGroupResponse:', addUserToSubGroupResponse);
    
    return res.status(204).json({ message: `User ${username} added to subGroup ${subGroupName}` }); // Fixed: was user_email
  } catch (error) {
    console.error("Error in modifying user group", error);
    return res.status(error.status || 500).json({ message: "Unable to add user to group" });
  }
});