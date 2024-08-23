import streamlit as st
import pandas as pd
import sqlite3
from sqlalchemy import create_engine
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import streamlit as st
import pandas as pd
import plotly.express as px
from auth import check_authentication

# Check authentication
check_authentication()


# Database connection
def init_db():
    conn = sqlite3.connect('grant_management.db')
    return conn

# Function to create tables if they don't exist
def create_table(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS applicants (
                    unique_id TEXT PRIMARY KEY,
                    grant_program TEXT,
                    project_name TEXT,
                    applicant_organization_name TEXT,
                    organization_type TEXT,
                    mea_pm TEXT,
                    street TEXT,
                    city TEXT,
                    zip TEXT,
                    primary_contact_person TEXT,
                    primary_contact_email TEXT,
                    primary_contact_phone_number TEXT,
                    signatory_contact_name TEXT,
                    signatory_contact_title TEXT,
                    signatory_contact_email TEXT,
                    signatory_contact_phone_number TEXT,
                    additional_contact_name TEXT,
                    additional_contact_title TEXT,
                    additional_contact_email TEXT,
                    additional_contact_phone_number TEXT,
                    application_status TEXT,
                    last_communication_date DATE,
                    next_scheduled_communication_date DATE,
                    communication_type TEXT,
                    communication_notes TEXT,
                    additional_notes TEXT
                )''')

# Function to load data
def load_data(conn):
    return pd.read_sql("SELECT * FROM applicants", conn)

# Function to add a new applicant
def add_applicant(conn):
    st.header("Add New Applicant")
    
    new_applicant = {
        'unique_id': st.text_input("Unique ID"),
        'grant_program': st.text_input("Grant Program"),
        'project_name': st.text_input("Project Name"),
        'applicant_organization_name': st.text_input("Applicant Organization Name"),
        'organization_type': st.selectbox("Organization Type", options=['Nonprofit', 'Government', 'Private', 'Educational Institution']),
        'mea_pm': st.text_input("MEA PM"),
        'street': st.text_input("Street"),
        'city': st.text_input("City"),
        'zip': st.text_input("Zip"),
        'primary_contact_person': st.text_input("Primary Contact Person"),
        'primary_contact_email': st.text_input("Primary Contact Email"),
        'primary_contact_phone_number': st.text_input("Primary Contact Phone Number"),
        'signatory_contact_name': st.text_input("Signatory Contact Name"),
        'signatory_contact_title': st.text_input("Signatory Contact Title"),
        'signatory_contact_email': st.text_input("Signatory Contact Email"),
        'signatory_contact_phone_number': st.text_input("Signatory Contact Phone Number"),
        'additional_contact_name': st.text_input("Additional Contact Name"),
        'additional_contact_title': st.text_input("Additional Contact Title"),
        'additional_contact_email': st.text_input("Additional Contact Email"),
        'additional_contact_phone_number': st.text_input("Additional Contact Phone Number"),
        'application_status': st.selectbox("Application Status", options=['Submitted', 'Under Review', 'Approved', 'Rejected']),
        'last_communication_date': st.date_input("Last Communication Date"),
        'next_scheduled_communication_date': st.date_input("Next Scheduled Communication Date"),
        'communication_type': st.text_input("Communication Type"),
        'communication_notes': st.text_area("Communication Notes"),
        'additional_notes': st.text_area("Additional Notes"),
    }

    if st.button("Add Applicant"):
        placeholders = ', '.join('?' * len(new_applicant))
        columns = ', '.join(new_applicant.keys())
        sql = f"INSERT INTO applicants ({columns}) VALUES ({placeholders})"
        conn.execute(sql, tuple(new_applicant.values()))
        conn.commit()
        st.success("New applicant added successfully!")

# Function to send emails
def send_emails(data):
    st.header("Send Email to All Contacts")
    
    sender_email = st.text_input("Your Email")
    password = st.text_input("Your Email Password", type="password")
    subject = st.text_input("Email Subject")
    message_body = st.text_area("Email Message")

    if st.button("Send Emails"):
        if not sender_email or not password or not subject or not message_body:
            st.error("Please fill in all the fields.")
        else:
            contacts = data[['primary_contact_email', 'signatory_contact_email', 'additional_contact_email']].stack().unique()
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.login(sender_email, password)
            
            for email in contacts:
                if pd.notna(email):  # Ensure the email is not NaN
                    msg = MIMEMultipart()
                    msg['From'] = sender_email
                    msg['To'] = email
                    msg['Subject'] = subject
                    msg.attach(MIMEText(message_body, 'plain'))
                    server.sendmail(sender_email, email, msg.as_string())
            
            server.quit()
            st.success("Emails sent successfully!")

# Main application
def main():
    st.title("Grant Management CRM")

    conn = init_db()
    create_table(conn)
    
    # Load the data
    data = load_data(conn)
    
    if not data.empty:
        st.write("Current Data")
        
        # Add options for sorting and filtering
        st.subheader("Filter and Sort Data")
        filter_column = st.selectbox("Filter by Column", options=data.columns)
        filter_value = st.text_input(f"Filter {filter_column} by")
        if filter_value:
            data = data[data[filter_column].astype(str).str.contains(filter_value, case=False)]
        
        sort_column = st.selectbox("Sort by Column", options=data.columns)
        sort_ascending = st.radio("Sort Order", options=['Ascending', 'Descending'])
        data = data.sort_values(by=sort_column, ascending=(sort_ascending == 'Ascending'))
        
        st.write(data)
        
        # Add new applicant
        add_applicant(conn)
        
        # Send emails
        send_emails(data)

if __name__ == "__main__":
    main()
