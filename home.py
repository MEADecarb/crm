import streamlit as st
from auth import init_db, login_page, register_page, logout, check_authentication

# Initialize the database
init_db()

# Sidebar for navigation and authentication
def sidebar():
  with st.sidebar:
      if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
          page = st.radio("Go to", ["Login", "Register"])
          if page == "Login":
              login_page()
          elif page == "Register":
              register_page()
      else:
          st.write(f"Welcome, {st.session_state['user'][1]}!")
          if st.button("Logout"):
              logout()
              st.experimental_rerun()

# Main content
def main_content():
  if check_authentication():
      st.title('MEA Decarb CRM')
      st.write('Welcome to the MEA Decarb Customer Relationship Management System')
      
      # Your main application code here
      st.write(f"You are logged in as: {st.session_state['user'][1]}")
      st.write("Your role is:", st.session_state['user'][3])
      
      # Add more of your CRM functionality here

# Main app
def main():
  sidebar()
  main_content()

if __name__ == "__main__":
  main()
