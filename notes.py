import streamlit as st
import sqlite3
import pandas as pd
import json
import base64
import hashlib
import requests
import os
from cryptography.fernet import Fernet
from datetime import datetime
import tempfile

# Page configuration
st.set_page_config(
    page_title="Data Engineer's Notes App",
    page_icon="📊",
    layout="wide"
)

# Initialize encryption
def setup_encryption():
    if 'encryption_key' not in st.session_state:
        # Generate or retrieve encryption key
        if 'ENCRYPTION_KEY' in st.secrets:
            key = st.secrets['ENCRYPTION_KEY'].encode()
        else:
            key = Fernet.generate_key()
            st.warning("⚠️ Encryption key not found in secrets. Using a temporary key. For production, set ENCRYPTION_KEY in secrets.toml")
        
        st.session_state.encryption_key = key
    
    return Fernet(st.session_state.encryption_key)

cipher_suite = setup_encryption()

# GitHub integration functions
def get_github_auth_headers():
    """Return authentication headers for GitHub API"""
    token = st.secrets.get("GITHUB_TOKEN")
    if not token:
        st.error("GitHub token not found in secrets!")
        return None
    
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

def download_db_from_github():
    """Download database from GitHub"""
    repo = st.secrets.get("GITHUB_REPO")
    if not repo:
        st.error("GitHub repository not configured!")
        return False
    
    headers = get_github_auth_headers()
    if not headers:
        return False
    
    url = f"https://api.github.com/repos/{repo}/contents/data_engineer_notes.db"
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            content = response.json().get("content", "")
            if content:
                decoded = base64.b64decode(content)
                with open("data_engineer_notes.db", "wb") as f:
                    f.write(decoded)
                st.sidebar.success("Database downloaded from GitHub!")
                return True
        elif response.status_code == 404:
            st.sidebar.info("No existing database found on GitHub. A new one will be created.")
            return True
        else:
            st.sidebar.error(f"Failed to download database: {response.status_code}")
            return False
    except Exception as e:
        st.sidebar.error(f"Error downloading from GitHub: {str(e)}")
        return False

def upload_db_to_github():
    """Upload database to GitHub"""
    repo = st.secrets.get("GITHUB_REPO")
    if not repo:
        st.error("GitHub repository not configured!")
        return False
    
    headers = get_github_auth_headers()
    if not headers:
        return False
    
    # Check if file exists to get its SHA (required for updates)
    url = f"https://api.github.com/repos/{repo}/contents/data_engineer_notes.db"
    response = requests.get(url, headers=headers)
    sha = None
    if response.status_code == 200:
        sha = response.json().get("sha")
    
    # Read and encode file content
    try:
        with open("data_engineer_notes.db", "rb") as f:
            content = base64.b64encode(f.read()).decode("utf-8")
    except FileNotFoundError:
        st.error("Database file not found!")
        return False
    
    # Prepare data for upload
    data = {
        "message": f"Update database - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "content": content,
        "sha": sha  # This will be None for new files
    }
    
    # Upload file
    try:
        response = requests.put(url, headers=headers, json=data)
        if response.status_code in [200, 201]:
            st.sidebar.success("Database uploaded to GitHub!")
            return True
        else:
            error_msg = response.json().get("message", "Unknown error")
            st.sidebar.error(f"Failed to upload database: {error_msg}")
            return False
    except Exception as e:
        st.sidebar.error(f"Error uploading to GitHub: {str(e)}")
        return False

def setup_github_sync():
    """Add GitHub sync functionality to sidebar"""
    st.sidebar.subheader("GitHub Sync")
    
    if st.sidebar.button("📥 Download from GitHub"):
        if download_db_from_github():
            st.rerun()  # Reload the app to use the new database
    
    if st.sidebar.button("📤 Upload to GitHub"):
        upload_db_to_github()
    
    # Add automatic sync option
    auto_sync = st.sidebar.checkbox("Auto-sync with GitHub", value=False)
    if auto_sync:
        st.sidebar.info("Auto-sync will upload changes when you make them")
    
    return auto_sync

# Database setup
def init_db():
    # Create database if it doesn't exist
    conn = sqlite3.connect('data_engineer_notes.db')
    c = conn.cursor()
    
    # Links table
    c.execute('''CREATE TABLE IF NOT EXISTS links
                 (id INTEGER PRIMARY KEY, title TEXT, url TEXT, category TEXT, 
                  description TEXT, created_at TIMESTAMP)''')
    
    # Passwords table (encrypted)
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY, service TEXT, username TEXT, 
                  password_encrypted TEXT, notes TEXT, created_at TIMESTAMP)''')
    
    # Files metadata table
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY, filename TEXT, file_type TEXT, 
                  description TEXT, tags TEXT, created_at TIMESTAMP)''')
    
    # SQL snippets table
    c.execute('''CREATE TABLE IF NOT EXISTS sql_snippets
                 (id INTEGER PRIMARY KEY, title TEXT, sql_code TEXT, 
                  database_type TEXT, description TEXT, tags TEXT, created_at TIMESTAMP)''')
    
    # Airflow DAGs table
    c.execute('''CREATE TABLE IF NOT EXISTS airflow_dags
                 (id INTEGER PRIMARY KEY, dag_name TEXT, description TEXT, 
                  schedule TEXT, owner TEXT, tags TEXT, created_at TIMESTAMP)''')
    
    # Snowflake configurations table
    c.execute('''CREATE TABLE IF NOT EXISTS snowflake_configs
                 (id INTEGER PRIMARY KEY, config_name TEXT, account_url TEXT, 
                  warehouse TEXT, database TEXT, schema TEXT, role TEXT, notes TEXT, created_at TIMESTAMP)''')
    
    # Data pipeline documentation table
    c.execute('''CREATE TABLE IF NOT EXISTS data_pipelines
                 (id INTEGER PRIMARY KEY, pipeline_name TEXT, description TEXT, 
                  source TEXT, destination TEXT, transformation_logic TEXT, 
                  schedule TEXT, owner TEXT, tags TEXT, created_at TIMESTAMP)''')
    
    conn.commit()
    return conn

# Helper functions
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password).decode()

def execute_with_github_backup(query, params=None):
    """Execute SQL query and optionally backup to GitHub"""
    conn = st.session_state.db_conn
    if params:
        conn.execute(query, params)
    else:
        conn.execute(query)
    conn.commit()
    
    # Backup to GitHub if auto-sync is enabled
    if st.session_state.get('auto_sync', False):
        upload_db_to_github()

# Initialize the app
def init_app():
    # Initialize GitHub integration
    if "GITHUB_TOKEN" in st.secrets and "GITHUB_REPO" in st.secrets:
        auto_sync = setup_github_sync()
        st.session_state.auto_sync = auto_sync
        
        # Download database on first run
        if "github_init" not in st.session_state:
            download_db_from_github()
            st.session_state.github_init = True
    else:
        st.sidebar.warning("GitHub integration not configured. Add GITHUB_TOKEN and GITHUB_REPO to secrets.toml")
    
    # Initialize database connection
    if "db_conn" not in st.session_state:
        st.session_state.db_conn = init_db()
    
    return st.session_state.db_conn

# Navigation
def main():
    conn = init_app()
    
    st.sidebar.title("🔧 Data Engineer's Toolkit")
    page = st.sidebar.radio("Navigate to:", [
        "Dashboard", "Links", "Passwords", "Files", 
        "SQL Snippets", "Airflow DAGs", "Snowflake Configs",
        "Data Pipelines"
    ])

    # Dashboard
    if page == "Dashboard":
        st.title("📊 Data Engineer's Dashboard")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Links", conn.execute("SELECT COUNT(*) FROM links").fetchone()[0])
            st.metric("SQL Snippets", conn.execute("SELECT COUNT(*) FROM sql_snippets").fetchone()[0])
        
        with col2:
            st.metric("Airflow DAGs", conn.execute("SELECT COUNT(*) FROM airflow_dags").fetchone()[0])
            st.metric("Files Stored", conn.execute("SELECT COUNT(*) FROM files").fetchone()[0])
        
        with col3:
            st.metric("Snowflake Configs", conn.execute("SELECT COUNT(*) FROM snowflake_configs").fetchone()[0])
            st.metric("Passwords", conn.execute("SELECT COUNT(*) FROM passwords").fetchone()[0])
            
        with col4:
            st.metric("Data Pipelines", conn.execute("SELECT COUNT(*) FROM data_pipelines").fetchone()[0])
            st.metric("GitHub Sync", "✅" if st.session_state.get('auto_sync', False) else "❌")
        
        # Recent activity
        st.subheader("Recent Activity")
        recent_activities = []
        
        # Get recent items from all tables
        for table in ['links', 'sql_snippets', 'airflow_dags', 'files', 'data_pipelines']:
            items = conn.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 3").fetchall()
            for item in items:
                recent_activities.append({
                    'type': table,
                    'title': item[1],
                    'timestamp': item[-1]
                })
        
        for activity in sorted(recent_activities, key=lambda x: x['timestamp'], reverse=True)[:5]:
            st.write(f"📅 {activity['timestamp']} - {activity['type'].title()}: {activity['title']}")

    # Links Management
    elif page == "Links":
        st.title("🔗 Important Links")
        
        tab1, tab2 = st.tabs(["Add New Link", "View Links"])
        
        with tab1:
            with st.form("link_form"):
                title = st.text_input("Title")
                url = st.text_input("URL")
                category = st.selectbox("Category", [
                    "Documentation", "GitHub", "Dashboard", "Monitoring", 
                    "Data Catalog", "CI/CD", "Internal Tool", "External Service", "Other"
                ])
                description = st.text_area("Description")
                
                if st.form_submit_button("Save Link"):
                    execute_with_github_backup(
                        "INSERT INTO links (title, url, category, description, created_at) VALUES (?, ?, ?, ?, ?)",
                        (title, url, category, description, datetime.now())
                    )
                    st.success("Link saved!")
        
        with tab2:
            links = conn.execute("SELECT * FROM links ORDER BY created_at DESC").fetchall()
            for link in links:
                with st.expander(f"{link[1]} ({link[3]})"):
                    st.write(f"**URL:** [{link[2]}]({link[2]})")
                    st.write(f"**Description:** {link[4]}")
                    st.write(f"**Created:** {link[5]}")
                    if st.button("Delete", key=f"del_link_{link[0]}"):
                        execute_with_github_backup("DELETE FROM links WHERE id = ?", (link[0],))
                        st.rerun()

    # Password Management (with encryption)
    elif page == "Passwords":
        st.title("🔐 Password Manager")
        
        tab1, tab2 = st.tabs(["Add Password", "View Passwords"])
        
        with tab1:
            with st.form("password_form"):
                service = st.text_input("Service/Application")
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                notes = st.text_area("Notes")
                
                if st.form_submit_button("Save Password"):
                    encrypted_pw = encrypt_password(password)
                    execute_with_github_backup(
                        "INSERT INTO passwords (service, username, password_encrypted, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                        (service, username, encrypted_pw, notes, datetime.now())
                    )
                    st.success("Password saved securely!")
        
        with tab2:
            passwords = conn.execute("SELECT * FROM passwords ORDER BY service").fetchall()
            for pw in passwords:
                with st.expander(f"{pw[1]} - {pw[2]}"):
                    decrypted_pw = decrypt_password(pw[3])
                    st.write(f"**Username:** {pw[2]}")
                    st.write(f"**Password:** `{decrypted_pw}`")
                    st.write(f"**Notes:** {pw[4]}")
                    st.write(f"**Created:** {pw[5]}")
                    if st.button("Delete", key=f"del_pw_{pw[0]}"):
                        execute_with_github_backup("DELETE FROM passwords WHERE id = ?", (pw[0],))
                        st.rerun()

    # File Management
    elif page == "Files":
        st.title("📁 File Storage")
        
        uploaded_file = st.file_uploader("Upload a file", type=[
            'py', 'sql', 'json', 'yaml', 'yml', 'txt', 'csv', 'md',
            'ipynb', 'xml', 'conf', 'cfg', 'ini', 'zip'
        ])
        
        if uploaded_file:
            # Save file to temporary location
            file_bytes = uploaded_file.getvalue()
            file_type = uploaded_file.type
            description = st.text_input("File description")
            tags = st.text_input("Tags (comma-separated)")
            
            if st.button("Save File Metadata"):
                execute_with_github_backup(
                    "INSERT INTO files (filename, file_type, description, tags, created_at) VALUES (?, ?, ?, ?, ?)",
                    (uploaded_file.name, file_type, description, tags, datetime.now())
                )
                st.success("File metadata saved!")
        
        # List files
        st.subheader("Stored Files")
        files = conn.execute("SELECT * FROM files ORDER BY created_at DESC").fetchall()
        for file in files:
            with st.expander(f"{file[1]} ({file[2]})"):
                st.write(f"**Description:** {file[3]}")
                st.write(f"**Tags:** {file[4]}")
                st.write(f"**Created:** {file[5]}")
                if st.button("Delete", key=f"del_file_{file[0]}"):
                    execute_with_github_backup("DELETE FROM files WHERE id = ?", (file[0],))
                    st.rerun()

    # SQL Snippets
    elif page == "SQL Snippets":
        st.title("💾 SQL Snippets")
        
        tab1, tab2 = st.tabs(["Add Snippet", "View Snippets"])
        
        with tab1:
            with st.form("sql_form"):
                title = st.text_input("Snippet Title")
                database_type = st.selectbox("Database", [
                    "Snowflake", "PostgreSQL", "MySQL", "Oracle", "SQL Server", "BigQuery", "Redshift"
                ])
                sql_code = st.text_area("SQL Code", height=200, placeholder="SELECT * FROM table WHERE condition;")
                description = st.text_area("Description")
                tags = st.text_input("Tags (comma-separated)", placeholder="optimization, reporting, etl")
                
                if st.form_submit_button("Save Snippet"):
                    execute_with_github_backup(
                        "INSERT INTO sql_snippets (title, sql_code, database_type, description, tags, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (title, sql_code, database_type, description, tags, datetime.now())
                    )
                    st.success("SQL snippet saved!")
        
        with tab2:
            snippets = conn.execute("SELECT * FROM sql_snippets ORDER BY created_at DESC").fetchall()
            for snippet in snippets:
                with st.expander(f"{snippet[1]} ({snippet[3]})"):
                    st.code(snippet[2], language='sql')
                    st.write(f"**Description:** {snippet[4]}")
                    st.write(f"**Tags:** {snippet[5]}")
                    st.write(f"**Created:** {snippet[6]}")
                    if st.button("Delete", key=f"del_sql_{snippet[0]}"):
                        execute_with_github_backup("DELETE FROM sql_snippets WHERE id = ?", (snippet[0],))
                        st.rerun()

    # Airflow DAGs
    elif page == "Airflow DAGs":
        st.title("🌪️ Airflow DAGs")
        
        tab1, tab2 = st.tabs(["Add DAG Info", "View DAGs"])
        
        with tab1:
            with st.form("dag_form"):
                dag_name = st.text_input("DAG Name")
                description = st.text_area("Description")
                schedule = st.text_input("Schedule (cron syntax)", value="0 0 * * *", placeholder="0 0 * * *")
                owner = st.text_input("Owner", value="data_engineering")
                tags = st.text_input("Tags (comma-separated)", placeholder="extract, load, daily")
                
                if st.form_submit_button("Save DAG Info"):
                    execute_with_github_backup(
                        "INSERT INTO airflow_dags (dag_name, description, schedule, owner, tags, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (dag_name, description, schedule, owner, tags, datetime.now())
                    )
                    st.success("DAG information saved!")
        
        with tab2:
            dags = conn.execute("SELECT * FROM airflow_dags ORDER BY created_at DESC").fetchall()
            for dag in dags:
                with st.expander(f"{dag[1]}"):
                    st.write(f"**Description:** {dag[2]}")
                    st.write(f"**Schedule:** `{dag[3]}`")
                    st.write(f"**Owner:** {dag[4]}")
                    st.write(f"**Tags:** {dag[5]}")
                    st.write(f"**Created:** {dag[6]}")
                    if st.button("Delete", key=f"del_dag_{dag[0]}"):
                        execute_with_github_backup("DELETE FROM airflow_dags WHERE id = ?", (dag[0],))
                        st.rerun()

    # Snowflake Configurations
    elif page == "Snowflake Configs":
        st.title("❄️ Snowflake Configurations")
        
        tab1, tab2 = st.tabs(["Add Config", "View Configs"])
        
        with tab1:
            with st.form("snowflake_form"):
                config_name = st.text_input("Configuration Name")
                account_url = st.text_input("Account URL", placeholder="https://your-account.snowflakecomputing.com")
                warehouse = st.text_input("Warehouse", value="COMPUTE_WH")
                database = st.text_input("Database")
                schema = st.text_input("Schema", value="PUBLIC")
                role = st.text_input("Role", value="SYSADMIN")
                notes = st.text_area("Notes")
                
                if st.form_submit_button("Save Configuration"):
                    execute_with_github_backup(
                        "INSERT INTO snowflake_configs (config_name, account_url, warehouse, database, schema, role, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (config_name, account_url, warehouse, database, schema, role, notes, datetime.now())
                    )
                    st.success("Snowflake configuration saved!")
        
        with tab2:
            configs = conn.execute("SELECT * FROM snowflake_configs ORDER BY created_at DESC").fetchall()
            for config in configs:
                with st.expander(f"{config[1]}"):
                    st.write(f"**Account URL:** {config[2]}")
                    st.write(f"**Warehouse:** {config[3]}")
                    st.write(f"**Database:** {config[4]}")
                    st.write(f"**Schema:** {config[5]}")
                    st.write(f"**Role:** {config[6]}")
                    st.write(f"**Notes:** {config[7]}")
                    st.write(f"**Created:** {config[8]}")
                    if st.button("Delete", key=f"del_snow_{config[0]}"):
                        execute_with_github_backup("DELETE FROM snowflake_configs WHERE id = ?", (config[0],))
                        st.rerun()

    # Data Pipelines
    elif page == "Data Pipelines":
        st.title("📊 Data Pipelines")
        
        tab1, tab2 = st.tabs(["Add Pipeline", "View Pipelines"])
        
        with tab1:
            with st.form("pipeline_form"):
                pipeline_name = st.text_input("Pipeline Name")
                description = st.text_area("Description")
                source = st.text_input("Source System")
                destination = st.text_input("Destination System")
                transformation_logic = st.text_area("Transformation Logic", height=150)
                schedule = st.text_input("Schedule", value="Daily")
                owner = st.text_input("Owner", value="data_engineering")
                tags = st.text_input("Tags (comma-separated)", placeholder="etl, analytics, reporting")
                
                if st.form_submit_button("Save Pipeline"):
                    execute_with_github_backup(
                        "INSERT INTO data_pipelines (pipeline_name, description, source, destination, transformation_logic, schedule, owner, tags, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (pipeline_name, description, source, destination, transformation_logic, schedule, owner, tags, datetime.now())
                    )
                    st.success("Pipeline information saved!")
        
        with tab2:
            pipelines = conn.execute("SELECT * FROM data_pipelines ORDER BY created_at DESC").fetchall()
            for pipeline in pipelines:
                with st.expander(f"{pipeline[1]}"):
                    st.write(f"**Description:** {pipeline[2]}")
                    st.write(f"**Source:** {pipeline[3]}")
                    st.write(f"**Destination:** {pipeline[4]}")
                    st.write(f"**Transformation Logic:** {pipeline[5]}")
                    st.write(f"**Schedule:** {pipeline[6]}")
                    st.write(f"**Owner:** {pipeline[7]}")
                    st.write(f"**Tags:** {pipeline[8]}")
                    st.write(f"**Created:** {pipeline[9]}")
                    if st.button("Delete", key=f"del_pipeline_{pipeline[0]}"):
                        execute_with_github_backup("DELETE FROM data_pipelines WHERE id = ?", (pipeline[0],))
                        st.rerun()

    # Footer
    st.sidebar.markdown("---")
    st.sidebar.info("🔒 Passwords are encrypted using Fernet encryption")
    st.sidebar.info("💾 Data stored in SQLite database synced with GitHub")

if __name__ == "__main__":
    main()
