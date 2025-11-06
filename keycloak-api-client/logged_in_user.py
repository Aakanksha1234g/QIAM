#logged_in user
username = None
email = None
def set_logged_in_user_details(logged_in_user,email_id):
    print("Current user details are:")
    global username, email
    username = logged_in_user
    email = email_id
    print("username:",username)
    print("email:",email)

def login_details(state):
    if state == True:
        print("access token state is true")
        print(f"returning username {username}, email {email}")
        return {
            "username":username,
            "email":email
        }
    else:
        print("access token state is false")
        return {
            "username":"No user logged in",
            "email":""
        }