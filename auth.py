import streamlit as st
import sqlite3
import bcrypt
import pyotp
from collections import defaultdict
import time
import re

# Enable logging
import logging
logging.basicConfig(level=logging.INFO)

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, totp_secret TEXT, is_2fa_enabled BOOLEAN)''')
    conn.commit()
    conn.close()
    logging.info("Database initialized")

# Password strength check
def is_password_strong(password):
    if len(password) < 8:
        return False
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
        return False
    return True

# Rate limiting
login_attempts = defaultdict(list)

def is_rate_limited(username):
    now = time.time()
    login_attempts[username] = [t for t in login_attempts[username] if now - t < 60]
    if len(login_attempts[username]) >= 5:
        return True
    login_attempts[username].append(now)
    return False

# User authentication
def authenticate(username, password, totp_token=None):
    if is_rate_limited(username):
        return None, "Too many login attempts. Please try again later."

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if user:
        logging.info(f"User found: {user}")
        if bcrypt.checkpw(password.encode(), user[2]):
            if user[5]:  # 2FA is enabled
                if totp_token:
                    if verify_totp(user[4], totp_token):
                        logging.info("2FA verification successful")
                        return user, None
                    else:
                        logging.warning("Invalid 2FA token")
                        return None, "Invalid 2FA token"
                else:
                    logging.info("2FA is enabled but no token provided")
                    return user, "2FA_REQUIRED"
            else:
                logging.info("2FA not enabled for user")
                return user, "2FA_SETUP_REQUIRED"
        else:
            logging.warning("Invalid password")
            return None, "Invalid username or password"
    else:
        logging.warning("User not found")
        return None, "Invalid username or password"

def verify_totp(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

# Setup 2FA
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
            st.session_state['user'] = (user[0], user[1], user[2], user[3], totp_secret, True)
            st.session_state['authenticated'] = True
            logging.info(f"2FA enabled for user {user[1]}")
        else:
            st.error("Invalid verification code. Please try again.")
            logging.warning(f"Failed 2FA setup attempt for user {user[1]}")

# Login page
def login_page():
    if 'authenticated' in st.session_state and st.session_state['authenticated']:
        st.success("You are already logged in.")
        return True

    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        user, error = authenticate(username, password)
        
        if user and error == "2FA_SETUP_REQUIRED":
            st.success("First-time login detected. Let's set up 2FA.")
            setup_2fa(user)
        elif user and error == "2FA_REQUIRED":
            totp_token = st.text_input("2FA Token")
            if st.button("Verify 2FA"):
                user, error = authenticate(username, password, totp_token)
                if user:
                    st.session_state['user'] = user
                    st.session_state['authenticated'] = True
                    st.success("Logged in successfully!")
                    logging.info(f"User {username} logged in successfully")
                    return True
                else:
                    st.error(error)
                    logging.warning(f"Failed login attempt for user {username}")
        elif user:
            st.session_state['user'] = user
            st.session_state['authenticated'] = True
            st.success("Logged in successfully!")
            logging.info(f"User {username} logged in successfully (no 2FA)")
            return True
        else:
            st.error(error)
            logging.warning(f"Failed login attempt for user {username}")
    
    return False

# Registration page
def register_page():
    st.title("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if not is_password_strong(password):
        st.warning("Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character.")
    else:
        if st.button("Register"):
            conn = sqlite3.connect('users.db')
            c = conn.
