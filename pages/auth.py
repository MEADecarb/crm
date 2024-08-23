import streamlit as st
import sqlite3
import bcrypt
import pyotp
from collections import defaultdict
import time
import re

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, totp_secret TEXT)''')
    conn.commit()
    conn.close()

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
def authenticate(username, password, totp_token):
    if is_rate_limited(username):
        return None, "Too many login attempts. Please try again later."

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode(), user[2]):
        if verify_totp(user[4], totp_token):
            return user, None
        else:
            return None, "Invalid 2FA token"
    return None, "Invalid username or password"

def verify_totp(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

# Login page
def login_page():
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
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
            c = conn.cursor()
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            totp_secret = pyotp.random_base32()
            try:
                c.execute("INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)",
                          (username, hashed_password, 'user', totp_secret))
                conn.commit()
                st.success(f"Registration successful! Your 2FA secret is: {totp_secret}")
                st.info("Please save this secret and use it to generate your 2FA tokens.")
            except sqlite3.IntegrityError:
                st.error("Username already exists")
            finally:
                conn.close()

def logout():
    st.session_state['user'] = None
    st.session_state['authenticated'] = False
