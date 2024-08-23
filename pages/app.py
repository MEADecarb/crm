import streamlit as st
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Function to load the data
def load_data():
    uploaded_file = st.file_uploader("Upload your CSV file", type=['csv'])
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        return data
    return pd.DataFrame()

# Function to add a new applicant
def add_applicant(data):
    st.header("Add New Applicant")
    
    new_applicant = {}
    new_applicant['Unique ID'] = st.text_input("Unique ID")
    new_applicant['Grant Program'] = st.text_input("Grant Program")
    new_applicant['Project Name'] = st.text_input("Project Name")
    new_applicant['Applicant Organization Name'] = st.text_input("Applicant Organization Name")
    new_applicant['Organization Type'] = st.selectbox("Organization Type", options=['Nonprofit', 'Government', 'Private', 'Educational Institution'])
    new_applicant['MEA PM'] = st.text_input("MEA PM")
    new_applicant['Street'] = st.text_input("Street")
    new_applicant['City'] = st.text_input("City")
    new_applicant['Zip'] = st.text_input("Zip")
    new_applicant['Primary Contact Person'] = st.text_input("Primary Contact Person")
    new_applicant['Primary Contact Email'] = st.text_input("Primary Contact Email")
    new_applicant['Primary Contact Phone Number'] = st.text_input("Primary Contact Phone Number")
    new_applicant['Signatory Contact Name'] = st.text_input("Signatory Contact Name")
    new_applicant['Signatory Contact Title'] = st.text_input("Signatory Contact Title")
    new_applicant['Signatory Contact Email'] = st.text_input("Signatory Contact Email")
    new_applicant['Signatory Contact Phone Number'] = st.text_input("Signatory Contact Phone Number")
    new_applicant['Additional Contact Name'] = st.text_input("Additional Contact Name")
    new_applicant['Additional Contact Title'] = st.text_input("Additional Contact Title")
    new_applicant['Additional Contact Email'] = st.text_input("Additional Contact Email")
    new_applicant['Additional Contact Phone Number'] = st.text_input("Additional Contact Phone Number")
    new_applicant['Application Status'] = st.selectbox("Application Status", options=['Submitted', 'Under Review', 'Approved', 'Rejected'])
    new_applicant['Last Communication Date'] = st.date_input("Last Communication Date")
    new_applicant['Next Scheduled Communication Date'] = st.date_input("Next Scheduled Communication Date")
    new_applicant['Communication Type'] = st.text_input("Communication Type")
    new_applicant['Communication Notes'] = st.text_area("Communication Notes")
    new_applicant['Additional Notes'] = st.text_area("Additional Notes")

    if st.button("Add Applicant"):
        data = data.append(new_applicant, ignore_index=True)
        st.success("New applicant added successfully!")
    return data

# Function to download updated data as CSV
def download_data(data):
    csv = data.to_csv(index=False)
    st.download_button(label="Download Updated CSV", data=csv, file_name='updated_grant_data.csv', mime='text/csv')

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
            contacts = data[['Primary Contact Email', 'Signatory Contact Email', 'Additional Contact Email']].stack().unique()
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

    # Load the data
    data = load_data()
    
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
        data = add_applicant(data)
        
        # Download updated data
        download_data(data)
        
        # Send emails
        send_emails(data)

if __name__ == "__main__":
    main()
