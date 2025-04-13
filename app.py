# -------------------- Import Required Libraries --------------------
import streamlit as st  # Streamlit for the web app interface
import hashlib  # To hash passwords and passkeys
import json  # For working with JSON data files
import os  # For checking file paths
from cryptography.fernet import Fernet  # To encrypt and decrypt data
from datetime import datetime, timedelta  # To manage time-based lockouts
import random  # For generating random strings (e.g., passwords)
import string  # For character sets used in password generation

# -------------------- Constants --------------------
USER_DB_FILE = "users.json"         # File to store user information (username, password hash, etc.)
DATA_DB_FILE = "stored_data.json"   # File to store encrypted data by users

# -------------------- Initialization Functions --------------------
# Function to load JSON file
def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)  # Load the JSON data from the file
    return {}  # Return an empty dictionary if file doesn't exist

# Function to save data to a JSON file
def save_json(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)  # Write the data to the JSON file with indentation

# Load user data and stored data from JSON files
users = load_json(USER_DB_FILE)
stored_data = load_json(DATA_DB_FILE)

# -------------------- Session State Initialization --------------------
# Check and initialize session states to track user authentication status
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# -------------------- Helper Functions --------------------

# Function to hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()  # Hash the passkey

# Function to get the Fernet cipher using a user's key
def get_cipher(user_key):
    return Fernet(user_key.encode())  # Return the Fernet cipher initialized with the user's key

# Function to generate a random user key
def generate_user_key():
    return Fernet.generate_key().decode()  # Generate a random Fernet key

# Function to generate a random strong password
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation  # Define character set
    return ''.join(random.choice(chars) for _ in range(length))  # Return a random password

# Function to evaluate the strength of a password
def evaluate_password_strength(password):
    feedback = []  # List to collect feedback messages
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters.")
    if not any(c.isupper() for c in password):
        feedback.append("Add at least one uppercase letter.")
    if not any(c.islower() for c in password):
        feedback.append("Add at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        feedback.append("Add at least one number.")
    if not any(c in string.punctuation for c in password):
        feedback.append("Add at least one special character.")

    if feedback:
        return "Weak", "\n".join(feedback)  # Return weak feedback
    return "Strong", "Great password!"  # Return strong password feedback

# Function to encrypt the data using the Fernet cipher
def encrypt_data(text, cipher):
    return cipher.encrypt(text.encode()).decode()  # Encrypt the data and return it as a string

# Function to decrypt the encrypted text if the passkey matches
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)  # Hash the provided passkey
    username = st.session_state.username
    user_data = stored_data.get(username, {})  # Get the user data from stored data

    # Check if the encrypted text exists in the user's stored data
    if encrypted_text in user_data:
        record = user_data[encrypted_text]
        if record["passkey"] == hashed:  # If passkey matches, decrypt the data
            st.session_state.failed_attempts = 0  # Reset failed attempts
            user_key = users[username]["key"]  # Get the user's key
            cipher = get_cipher(user_key)  # Create the cipher using the user's key
            return cipher.decrypt(encrypted_text.encode()).decode()  # Decrypt and return the data
    
    # If passkey is incorrect, increase failed attempt count and apply lockout if needed
    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= 3:
        st.session_state.lockout_time = datetime.now() + timedelta(seconds=30)  # Lockout for 30 seconds
    return None  # Return None if decryption failed

# -------------------- Login & Sign Up Page --------------------
# Check if the user is not authenticated, if so, show the login page
if not st.session_state.authenticated:
    st.set_page_config(page_title="Login", layout="centered")  # Configure page layout
    st.title("🔐 Secure Login System")  # Page title

    # Create tabs for Login and Sign Up
    tab1, tab2 = st.tabs(["Login", "Sign Up"])

    # -------------------- Sign Up Section --------------------
    with tab2:
        st.subheader("🧾 Create New Account")
        new_user = st.text_input("Username")  # Input for username
        new_pass = st.text_input("Password", type="password")  # Input for password
        strength, feedback = evaluate_password_strength(new_pass)  # Evaluate password strength

        # Display password strength and suggestions if user starts typing
        if new_pass:
            st.info(f"🔎 Strength: **{strength}**")
            st.write("💡 Suggestions:")
            for line in feedback.split("\n"):
                st.write(f"- {line}")

        # Register the new user if valid inputs are provided
        if st.button("Register"):
            if new_user and strength == "Strong":
                if new_user in users:  # Check if username already exists
                    st.error("⚠️ Username already exists.")
                else:
                    user_key = generate_user_key()  # Generate a new user key
                    users[new_user] = {
                        "password": hash_passkey(new_pass),  # Save hashed password
                        "key": user_key  # Save generated key for encryption
                    }
                    save_json(USER_DB_FILE, users)  # Save user data to file
                    stored_data[new_user] = {}  # Initialize empty data for new user
                    save_json(DATA_DB_FILE, stored_data)  # Save empty data to file
                    st.success("✅ Account created! Please log in.")  # Show success message
            else:
                st.error("❌ Please provide a unique username and strong password.")  # Error if invalid inputs

    # -------------------- Login Section --------------------
    with tab1:
        st.subheader("🔐 User Login")
        username = st.text_input("Username", key="login_user")  # Input for username
        password = st.text_input("Password", type="password", key="login_pass")  # Input for password

        # Check credentials and log the user in
        if st.button("Login"):
            if username in users and users[username]["password"] == hash_passkey(password):
                st.session_state.authenticated = True  # Set authenticated status
                st.session_state.username = username  # Store username in session state
                st.success("✅ Logged in successfully!")  # Show success message
                st.rerun()  # Rerun to refresh the page
            else:
                st.error("❌ Invalid credentials.")  # Show error if credentials are incorrect

# -------------------- Main App (After Login) --------------------
else:
    st.set_page_config(page_title="Secure Data Encryption", layout="centered")  # Configure page layout after login
    st.title(f"🛡️ Welcome, {st.session_state.username}")  # Welcome message

    # Navigation menu in the sidebar
    menu = ["Home", "Store Data", "Retrieve Data", "Download Data", "Logout"]
    choice = st.sidebar.selectbox("Navigation", menu)

    # -------------------- Logout --------------------
    if choice == "Logout":
        st.session_state.authenticated = False  # Reset authentication status
        st.session_state.username = ""  # Reset username
        st.success("✅ Logged out.")  # Show logout message
        st.rerun()  # Rerun to refresh the page

    # -------------------- Home Page --------------------
    elif choice == "Home":
        st.subheader("🏠 Dashboard")
        st.info("Use the sidebar to navigate between options.")  # Display information message

    # -------------------- Store Data Page --------------------
    elif choice == "Store Data":
        st.subheader("📂 Store Your Data")
        text = st.text_area("Enter data to encrypt")  # Input area for data to encrypt
        passkey = st.text_input("Enter passkey:", type="password")  # Input for passkey
        if st.button("Encrypt & Save"):
            if text and passkey:  # If data and passkey are provided
                user = st.session_state.username  # Get the logged-in username
                user_key = users[user]["key"]  # Get user-specific encryption key
                cipher = get_cipher(user_key)  # Initialize the cipher
                encrypted = encrypt_data(text, cipher)  # Encrypt the data
                hashed = hash_passkey(passkey)  # Hash the provided passkey
                stored_data[user][encrypted] = {
                    "encrypted_text": encrypted,  # Store encrypted data
                    "passkey": hashed,  # Store hashed passkey
                    "timestamp": datetime.now().isoformat()  # Store timestamp
                }
                save_json(DATA_DB_FILE, stored_data)  # Save the encrypted data to file
                st.success("✅ Data encrypted and stored!")  # Show success message
                st.code(encrypted, language="text")  # Display encrypted text
            else:
                st.error("⚠️ All fields are required.")  # Error if input fields are empty

    # -------------------- Retrieve Data Page ----------------
    # -------------------- Retrieve Data Page --------------------
    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Encrypted Data")

        user = st.session_state.username
        user_data = stored_data.get(user, {})

        if user_data:
            st.write("🔐 Encrypted Entries:")
            encrypted_options = list(user_data.keys())
            selected_encrypted = st.selectbox("Select encrypted entry", encrypted_options)

            passkey = st.text_input("Enter passkey to decrypt:", type="password")

            if st.button("Decrypt"):
                decrypted_text = decrypt_data(selected_encrypted, passkey)
                if decrypted_text:
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Text", decrypted_text, height=150)
                else:
                    if st.session_state.lockout_time and datetime.now() < st.session_state.lockout_time:
                        remaining = (st.session_state.lockout_time - datetime.now()).seconds
                        st.error(f"⏳ Too many attempts! Try again in {remaining} seconds.")
                    else:
                        st.error("❌ Incorrect passkey.")
        else:
            st.info("📭 No data stored yet.")

                 # -------------------- Download Data Page --------------------
    elif choice == "Download Data":
        st.subheader("📥 Download Stored Data")

        user = st.session_state.username
        user_data = stored_data.get(user, {})

        if user_data:
            data_text = json.dumps(user_data, indent=4)
            st.download_button(
                label="⬇️ Download Encrypted Data as JSON",
                data=data_text,
                file_name=f"{user}_encrypted_data.json",
                mime="application/json"
            )
        else:
            st.info("📭 No data available to download.")
