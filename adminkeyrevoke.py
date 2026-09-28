import os
from Database.db import get_connection, initialise_database
from Audit.auditlogfunc import log_action

base_directory = os.path.dirname(os.path.abspath(__file__))
keys_directory = os.path.join(base_directory, 'Data', 'Keys')
"""
This is a simulation of key revoke that is done by an admin user.
"""

def revoke_user(username):
    """
    The admin can revoke the users from the system.
    The keys and certificate are removed from Data/keys.
    This is action is logged.
    """
    connect = get_connection()
    cursor = connect.cursor()

    cursor.execute('SELECT * FROM users WHERE username = ?',(username,))
    user = cursor.fetchone()

    if user is None:
        print(f"ERROR User '{username} is not found.")
        connect.close()
        return
    #checks if already revoked
    if user["revoked"] == 1:
        print(f"User '{username} is already revoked.")
        connect.close()
        return
    
    cursor.execute('UPDATE users SET revoked = 1 WHERE username = ?',(username,))
    connect.commit()
    connect.close()

    key_files = [f"{username}_enc_private.pem",
                 f"{username}_enc_public.pem",
                 f"{username}_sign_private.pem",
                 f"{username}_sign_public.pem",
                 f"{username}_certificate.json"]
    for key_file in key_files:
        path =os.path.join(keys_directory,key_file)
        if os.path.exists(path):
            os.remove(path)
            print(f"Deleted {key_file}")
    
    log_action("system", "admin",f"revoked user account:{username}")
    print(f"\n User '{username}' has been revoked")
    print(f"All key files are now deleted.")
    print(f"Revocation logged in audit")

def lists_users():
    connect = get_connection()
    cursor = connect.cursor()
    cursor.execute('SELECT username, role, revoked FROM users')
    users = cursor.fetchall()
    connect.close()

    #print the status of the user, whether active or revoked
    print("\n== USER ACCOUNTS ==\n")
    print(f"{'Username':<15} {'Role':<15} {'Status'}")
    print("-" * 50)
    for user in users:
        status = "REVOKED" if user["revoked"] == 1 else "Active"
        print(f"{user['username']:<15}{user['role']:<15}{status}")

if __name__ == "__main__":
    initialise_database()
    print("\n=== KEY REVOCATION === ")
    print("This is an admin role operation.")
    print("All key revocations are logged in the audit log.")

    lists_users()

    username = input("\nEnter username to revoke ( or exit):").strip()
    if username.lower() == "exit" :
        print("Exit program.")
    else:
        confirm = input (f"Revoke'{username}'? (yes/no):").strip().lower()
        if confirm == 'yes':
            revoke_user(username)
        else:
            print("Revocation is cancelled.")
