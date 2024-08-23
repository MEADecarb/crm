import streamlit as st
import sqlite3
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import os
import json
import logging
import asyncio
import aiohttp
from typing import Dict, Any, Tuple, Optional
from contextlib import asynccontextmanager

# Enable logging
logging.basicConfig(level=logging.INFO)

# Set up Google OAuth2 credentials
CLIENT_CONFIG = {
  "web": {
      "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
      "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "redirect_uris": [os.environ.get("REDIRECT_URI", "https://meacrm.streamlit.app/")],
  }
}

# Database setup
@asynccontextmanager
async def get_db_connection():
  conn = await asyncio.to_thread(sqlite3.connect, 'users.db')
  try:
      yield conn
  finally:
      await asyncio.to_thread(conn.close)

async def init_db():
  async with get_db_connection() as conn:
      c = await conn.cursor()
      await c.execute('''CREATE TABLE IF NOT EXISTS users
                         (id INTEGER PRIMARY KEY, google_id TEXT UNIQUE, email TEXT UNIQUE, name TEXT, role TEXT)''')
      await conn.commit()
  logging.info("Database initialized")

# Google Sign-In
async def google_login() -> bool:
  flow = Flow.from_client_config(
      client_config=CLIENT_CONFIG,
      scopes=["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile", "openid"]
  )
  
  flow.redirect_uri = os.environ.get("REDIRECT_URI", "https://meacrm.streamlit.app/")

  query_params = st.experimental_get_query_params()
  if 'code' not in query_params:
      if st.button("Login with Google"):
          authorization_url, _ = flow.authorization_url(prompt="consent")
          st.write(f'<a href="{authorization_url}" target="_self">Click here to authenticate</a>', unsafe_allow_html=True)
      return False

  try:
      flow.fetch_token(code=query_params['code'][0])
      credentials = flow.credentials

      user_info = await get_user_info(credentials)
      if user_info:
          user = await save_or_get_user(user_info)
          st.session_state.user = user
          st.session_state.authenticated = True
          st.session_state.credentials = credentials.to_json()
          return True
  except Exception as e:
      logging.error(f"Error during Google login: {e}")
  return False

async def get_user_info(credentials: Credentials) -> Optional[Dict[str, Any]]:
  try:
      service = build('oauth2', 'v2', credentials=credentials)
      user_info = await asyncio.to_thread(service.userinfo().get().execute)
      return user_info
  except Exception as e:
      logging.error(f"Error getting user info: {e}")
      return None

async def save_or_get_user(user_info: Dict[str, Any]) -> Tuple[int, str, str, str, str]:
  async with get_db_connection() as conn:
      c = await conn.cursor()
      await c.execute("SELECT * FROM users WHERE google_id=?", (user_info['id'],))
      user = await c.fetchone()
      
      if not user:
          await c.execute("INSERT INTO users (google_id, email, name, role) VALUES (?, ?, ?, ?)",
                          (user_info['id'], user_info['email'], user_info['name'], 'user'))
          await conn.commit()
          user = (c.lastrowid, user_info['id'], user_info['email'], user_info['name'], 'user')
  
  return user

async def logout():
  if 'credentials' in st.session_state:
      credentials = Credentials.from_json(st.session_state.credentials)
      await revoke_token(credentials)
  
  for key in ['user', 'authenticated', 'credentials']:
      if key in st.session_state:
          del st.session_state[key]

async def revoke_token(credentials: Credentials):
  async with aiohttp.ClientSession() as session:
      revoke_url = f"https://oauth2.googleapis.com/revoke?token={credentials.token}"
      async with session.post(revoke_url) as resp:
          if resp.status == 200:
              logging.info("Successfully revoked token")
          else:
              logging.error(f"Failed to revoke token: {await resp.text()}")

# Authentication check
def check_authentication() -> bool:
  if 'authenticated' in st.session_state and st.session_state.authenticated:
      return True
  else:
      st.warning("Please log in to access this page.")
      st.stop()
      return False

# Role-based access control
def check_user_role(required_role: str) -> bool:
  if 'user' in st.session_state and st.session_state.user[4] == required_role:
      return True
  else:
      st.error("You don't have permission to access this page.")
      st.stop()
      return False

# Main app
async def main():
  await init_db()
  
  if not check_authentication():
      await google_login()
  else:
      if st.button("Logout"):
          await logout()
          st.experimental_rerun()

  # Your app logic here
  if check_user_role('admin'):
      st.write("Welcome, Admin!")
  elif check_user_role('user'):
      st.write("Welcome, User!")

if __name__ == "__main__":
  asyncio.run(main())
