import streamlit as st
import sqlite3
import bcrypt
import pyotp
from collections import defaultdict
import time
import re

# ... (keep the existing imports and database setup)

# Modify the users table to include a 'is_2fa_enabled' column
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, totp_secret TEXT, is_2fa_enabled BOOLEAN)''')
    conn.commit()
    conn.close()

# ... (keep the existing password strength and rate limiting functions)

# Modify the authenticate function
def authenticate(username, password, totp_token=None):
    if is_rate_limited(username):
        return None, "Too many login attempts. Please try again later."

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode(), user[2]):
        if user[5]:  # 2FA is enabled
            if totp_token and verify_totp(user[4], totp_token):
                return user, None
            else:
                return None, "Invalid 2FA token"
        else:  # 2FA is not enabled
            return user, None
    return None, "Invalid username or password"

# ... (keep the existing verify_totp function)

# Modify the login_page function
def login_page():
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    user, error = authenticate(username, password)
    
    if user:
        if not user[5]:  # 2FA is not enabled
            st.success("First-time login detected. Let's set up 2FA.")
            setup_2fa(user)
        else:
            totp_token = st.text_input("2FA Token")
            if st.button("Login"):
                user, error = authenticate(username, password, totp_token)
                if user:
                    st.session_state['user'] = user
                    st.success("Logged in successfully!")
                    st.session_state['authenticated'] = True
                    return True
                else:
                    st.error(error)
    elif error:
        st.error(error)
    
    return False

# Add a new function to set up 2FA
def setup_2fa(user):
    totp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(totp_secret)
    qr_code = totp.provisioning_uri(user[1], issuer_name="MEADecarb CRM")
    
    st.write("Scan this QR code with your authenticator app:")
    st.image(f"https://api.qrserver.com/v1/create-qr-code/?data={qr_code}&size=200x200")
    st.write(f"Or enter this secret manually: {totp_secret}")
    
    verification_code = st.text_input("Enter the verification code from your app:")
    if st.button("Verify and Enable 2FA"):
        if verify_totp(totp_secret, verification_code):
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("UPDATE users SET totp_secret = ?, is_2fa_enabled = ? WHERE id = ?", (totp_secret, True, user[0]))
            conn.commit()
            conn.close()
            st.success("2FA has been successfully enabled!")
            st.session_state['user'] = user
            st.session_state['authenticated'] = True
        else:
            st.error("Invalid verification code. Please try again.")

# Modify the register_page function
def register_page():
    st.title("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if not is_password_strong(password):
        st.warning("Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character.")
    else:
        if st.button("Register"):
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            try:
                c.execute("INSERT INTO users (username, password, role, totp_secret, is_2fa_enabled) VALUES (?, ?, ?, ?, ?)",
                          (username, hashed_password, 'user', '', False))
                conn.commit()
                st.success("Registration successful! Please log in to set up 2FA.")
            except sqlite3.IntegrityError:
                st.error("Username already exists")
            finally:
                conn.close()

# ... (keep the existing logout and check_authentication functions)
