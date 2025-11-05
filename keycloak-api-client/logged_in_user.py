#logged_in user
username = None
email = None

def set_logged_in_user_details(logged_in_user,email_id):
    print("Current user details are:")
    global username, email
    username = logged_in_user
    email = email_id
    
def login_details():
    return {
        "username":username,
        "email":email
    }
   