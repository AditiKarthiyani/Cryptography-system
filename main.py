from Database.db import initialise_database
from Authorisation.setupaccounts import setup_accountpassword
from Authorisation.login import login
from Roles.clinician import clinician_menu
from Roles.researcher import researcher_menu
from Roles.auditor import auditor_menu
from TLS.simulationtls import simulate_TLS


def main():
    """
    The main program - initialse the accounts, datatbase, the roles
    """
    initialise_database()
    setup_accountpassword()

    simulate_TLS()

    print("\n" + "=" * 50)
    print("    This is a Secure Clinical Research Platform")
    print("    Welcome to the system!")
    print("=" * 50)
    print("NOTE: This session is being logged for")
    print("compliance with GDPR Article 5(2).")
    print("By using this system, you consent to data processsing and audit logging.")

    # Login
    while True:
        session = login()

        if session is None:
                break
        
        role = session["role"]
        if role == "clinician":
            clinician_menu(session)
        elif role == "researcher":
            researcher_menu(session)
        elif role == "auditor":
            auditor_menu(session)
    
        #for the testing of the system, you can logout and login again.
        login_again = input("\nAnother user login? ( yes/no): ").strip().lower()
        if login_again != "yes":
            print("\n Thank you, you are leaving the system.")
            break

if __name__ == "__main__":
    main()