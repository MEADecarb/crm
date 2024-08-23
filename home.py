import streamlit as st
import pandas as pd
import plotly.express as px
from auth import init_db, login_page, register_page, logout, check_authentication

# Initialize the database
init_db()

# Sidebar for navigation and authentication
def sidebar():
  with st.sidebar:
      if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
          page = st.radio("Go to", ["Login", "Register"])
          if page == "Login":
              if login_page():
                  st.experimental_rerun()
          elif page == "Register":
              register_page()
      else:
          st.write(f"Welcome, {st.session_state['user'][1]}!")
          if st.button("Logout"):
              logout()
              st.experimental_rerun()

# Main content
def main_content():
  check_authentication()
  
  st.title('MEA Decarb CRM')
  st.write('Welcome to the MEA Decarb Customer Relationship Management System')

  # Load and display data
  df = pd.read_excel('data/sample_data.xlsx')
  st.write(df)

  # Create a bar chart
  fig = px.bar(df, x='Customer', y='Sales', title='Sales by Customer')
  st.plotly_chart(fig)

# Main app
def main():
  sidebar()
  main_content()

if __name__ == "__main__":
  main()
