# assignment-05
##🔐 **Secure Data Encryption System** – Step-by-Step Explanation

---

### **1. Project Initialization**
- `users.json` and `stored_data.json` files are used to save user credentials and encrypted data.
- Functions `load_json()` and `save_json()` handle reading and writing to JSON files.

---

### **2. Streamlit Session Setup**
- Session state variables maintain login state:
  - `authenticated` – is user logged in?
  - `username` – current logged-in user
  - `lockout_time` – to prevent brute force login attempts
  - `failed_attempts` – login failure count

---

### **3. Helper Functions**

#### 🔐 `hash_passkey(passkey)`
- SHA-256 hashing of passkey for secure matching.

#### 🔑 `generate_user_key()`
- Generates a unique Fernet key for each user for encryption/decryption.

#### 🔒 `get_cipher(user_key)`
- Returns Fernet cipher object using the user key.

#### 🔢 `generate_password(length)`
- Random strong password generator.

#### 💪 `evaluate_password_strength(password)`
- Checks for length, uppercase, lowercase, digit, special character.
- Returns strength (Weak/Strong) and suggestions.

#### 🔐 `encrypt_data(text, cipher)`
- Encrypts plain text using the Fernet cipher.

#### 🔓 `decrypt_data(encrypted_text, passkey)`
- Matches hashed passkey.
- Decrypts text if correct passkey is given.
- Adds failed attempts check with 30-second lockout.

---

### **4. User Interface – Login Page**
- **Sign Up Tab**:
  - Create account with username and strong password.
  - Password is checked for strength before saving.
  - A unique Fernet key is generated and saved for each user.
- **Login Tab**:
  - Match username + hashed password.
  - On success, login session is started.

---

### **5. Main App Pages (After Login)**

#### 🏠 **Home**
- Simple welcome dashboard.

#### 📂 **Store Data**
- Enter plain text + a passkey.
- Encrypt text with user key.
- Save:
  - `encrypted_text`
  - `hashed_passkey`
  - `timestamp`

#### 🔍 **Retrieve Data**
- User pastes encrypted text + correct passkey.
- If matched:
  - Data is decrypted and shown.
- If wrong:
  - Failed attempts increment.
  - Lock user for 30 seconds after 3 wrong tries.

#### 📥 **Download Data**
- User can download all their stored encrypted data as a `.json` file.

#### 🚪 **Logout**
- Resets session to log the user out.

---

## ✅ Features Implemented:
| Feature | Description |
|--------|-------------|
| ✅ User Authentication                    | Secure login & signup with hashed passwords |
| ✅ Password Strength Meter                | Shows suggestions for strong passwords |
| ✅ Unique Encryption Key                  | Per-user encryption using Fernet |
| ✅ Secure Encryption                      | AES-based encryption for each data entry |
| ✅ Passkey Protection                     | Decryption requires correct passkey |
| ✅ Brute Force Protection                 | Lock user after 3 wrong passkey attempts |
| ✅ Download Option                        | User can download their data in JSON |
| ✅ Fully Streamlit GUI | Easy-to-use interactive interface |

