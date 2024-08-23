import streamlit as st
from auth import init_db, login_page, register_page, logout
import app

def main():
  init_db()
  
  if 'authenticated' not in st.session_state:
      st.session_state['authenticated'] = False

  if not st.session_state['authenticated']:
      page = st.sidebar.radio("Go to", ["Login", "Register"])
      if page == "Login":
          if login_page():
              st.experimental_rerun()
      elif page == "Register":
          register_page()
  else:
      if st.sidebar.button("Logout"):
          logout()
          st.experimental_rerun()
      else:
          app.run()

if __name__ == "__main__":
  main()
