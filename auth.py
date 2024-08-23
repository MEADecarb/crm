import streamlit as st
import sqlite3
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import os
import json
import logging

# Enable logging
logging.basicConfig(level=logging.INFO)

# Set up Google OAuth2 credentials
CLIENT_CONFIG = {
  "web": {
      "client_id": st.secrets["google"]["client_id"],
      "client_secret": st.secrets["google"]["client_secret"],
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "redirect_uris": ["https://meacrm.streamlit.app/"],  # Update this for your deployed app
  }
}

# Database setup
def init_db():
  conn = sqlite3.connect('users.db')
  c = conn.cursor()
  c.execute('''CREATE TABLE IF NOT EXISTS users
               (id INTEGER PRIMARY KEY, google_id TEXT UNIQUE, email TEXT UNIQUE, name TEXT, role TEXT)''')
  conn.commit()
  conn.close()
  logging.info("Database initialized")

# Google Sign-In
def google_login():
  flow = Flow.from_client_config(
      client_config=CLIENT_CONFIG,
      scopes=["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile", "openid"]
  )
  
  flow.redirect_uri = "https://meacrm.streamlit.app/"  # Update this for your deployed app

  query_params = st.experimental_get_query_params()
  if 'code' not in query_params:
      if st.button("Login with Google"):
          authorization_url, _ = flow.authorization_url(prompt="consent")
          st.write(f'<a href="{authorization_url}" target="_self">Click here to authenticate</a>', unsafe_allow_html=True)
      return False

  flow.fetch_token(code=query_params['code'][0])
  credentials = flow.credentials

  user_info = get_user_info(credentials)
  if user_info:
      user = save_or_get_user(user_info)
      st.session_state.user = user
      st.session_state.authenticated = True
      return True
  return False

def get_user_info(credentials):
  try:
      service = build('oauth2', 'v2', credentials=credentials)
      user_info = service.userinfo().get().execute()
      return user_info
  except Exception as e:
      logging.error(f"Error getting user info: {e}")
      return None

def save_or_get_user(user_info):
  conn = sqlite3.connect('users.db')
  c = conn.cursor()
  c.execute("SELECT * FROM users WHERE google_id=?", (user_info['id'],))
  user = c.fetchone()
  
  if not user:
      c.execute("INSERT INTO users (google_id, email, name, role) VALUES (?, ?, ?, ?)",
                (user_info['id'], user_info['email'], user_info['name'], 'user'))
      conn.commit()
      user = (c.lastrowid, user_info['id'], user_info['email'], user_info['name'], 'user')
  
  conn.close()
  return user

def logout():
  for key in ['user', 'authenticated']:
      if key in st.session_state:
          del st.session_state[key]

# Authentication check
def check_authentication():
  if 'authenticated' in st.session_state and st.session_state.authenticated:
      return True
  else:
      st.warning("Please log in to access this page.")
      st.stop()
      return False
