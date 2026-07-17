import sys
from core.database import create_user
from core.auth import get_password_hash

def main():
    print("=== Threat Aggregator Admin Creation ===")
    username = input("Enter admin username [admin]: ").strip() or "admin"
    password = input("Enter admin password: ").strip()
    
    if not password:
        print("Password cannot be empty!")
        sys.exit(1)
        
    hashed = get_password_hash(password)
    user_id = create_user(username, hashed)
    
    if user_id:
        print(f"Success! Admin user '{username}' created.")
    else:
        print(f"Failed to create user. The username '{username}' might already exist.")

if __name__ == "__main__":
    main()
