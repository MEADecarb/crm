import streamlit as st
from auth import init_db, google_login, logout, check_authentication

# Initialize the database
init_db()

# Sidebar for navigation and authentication
def sidebar():
  with st.sidebar:
      if 'authenticated' not in st.session_state or not st.session_state.authenticated:
          if google_login():
              st.experimental_rerun()
      else:
          st.write(f"Welcome, {st.session_state.user[3]}!")
          if st.button("Logout"):
              logout()
              st.experimental_rerun()

# Main content
def main_content():
  if check_authentication():
      st.title('MEA Decarb CRM')
      st.write('Welcome to the MEA Decarb Customer Relationship Management System')
      
      # Your main application code here
      st.write(f"You are logged in as: {st.session_state.user[3]}")
      st.write("Your email is:", st.session_state.user[2])
      st.write("Your role is:", st.session_state.user[4])
      
      # Add more of your CRM functionality here

# Main app
def main():
  sidebar()
  main_content()

if __name__ == "__main__":
  main()
