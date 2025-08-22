import streamlit as st
import sqlite3
import base64
import requests
from cryptography.fernet import Fernet
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="Data Engineer's Notes App",
    page_icon="📊",
    layout="wide"
)

# Initialize encryption
def setup_encryption():
    if 'encryption_key' not in st.session_state:
        if 'ENCRYPTION_KEY' in st.secrets:
            key = st.secrets['ENCRYPTION_KEY'].encode()
        else:
            key = Fernet.generate_key()
            st.warning("⚠️ Using a temporary encryption key. Set ENCRYPTION_KEY in secrets.toml for production.")
        st.session_state.encryption_key = key
    return Fernet(st.session_state.encryption_key)

cipher_suite = setup_encryption()

# --- Database Helpers ---
def get_connection():
    return sqlite3.connect("data_engineer_notes.db", check_same_thread=False)

def init_db():
    with get_connection() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS links
                     (id INTEGER PRIMARY KEY, title TEXT, url TEXT, category TEXT, 
                      description TEXT, created_at TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                     (id INTEGER PRIMARY KEY, service TEXT, username TEXT, 
                      password_encrypted TEXT, notes TEXT, created_at TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS files
                     (id INTEGER PRIMARY KEY, filename TEXT, file_type TEXT, 
                      description TEXT, tags TEXT, created_at TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS sql_snippets
                     (id INTEGER PRIMARY KEY, title TEXT, sql_code TEXT, 
                      database_type TEXT, description TEXT, tags TEXT, created_at TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS airflow_dags
                     (id INTEGER PRIMARY KEY, dag_name TEXT, description TEXT, 
                      schedule TEXT, owner TEXT, tags TEXT, created_at TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS snowflake_configs
                     (id INTEGER PRIMARY KEY, config_name TEXT, account_url TEXT, 
                      warehouse TEXT, database TEXT, schema TEXT, role TEXT, notes TEXT, created_at TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS data_pipelines
                     (id INTEGER PRIMARY KEY, pipeline_name TEXT, description TEXT, 
                      source TEXT, destination TEXT, transformation_logic TEXT, 
                      schedule TEXT, owner TEXT, tags TEXT, created_at TIMESTAMP)''')
        conn.commit()

# Encryption helpers
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password).decode()

def execute_with_github_backup(query, params=None):
    with get_connection() as conn:
        if params:
            conn.execute(query, params)
        else:
            conn.execute(query)
        conn.commit()
    if st.session_state.get('auto_sync', False):
        upload_db_to_github()

# --- GitHub Integration ---
def get_github_auth_headers():
    token = st.secrets.get("GITHUB_TOKEN")
    if not token:
        st.error("GitHub token not found!")
        return None
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

def download_db_from_github():
    repo = st.secrets.get("GITHUB_REPO")
    if not repo:
        return False
    headers = get_github_auth_headers()
    if not headers:
        return False
    url = f"https://api.github.com/repos/{repo}/contents/data_engineer_notes.db"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        content = response.json().get("content", "")
        if content:
            decoded = base64.b64decode(content)
            with open("data_engineer_notes.db", "wb") as f:
                f.write(decoded)
            return True
    return False

def upload_db_to_github():
    repo = st.secrets.get("GITHUB_REPO")
    if not repo:
        return False
    headers = get_github_auth_headers()
    if not headers:
        return False
    url = f"https://api.github.com/repos/{repo}/contents/data_engineer_notes.db"
    response = requests.get(url, headers=headers)
    sha = response.json().get("sha") if response.status_code == 200 else None
    with open("data_engineer_notes.db", "rb") as f:
        content = base64.b64encode(f.read()).decode("utf-8")
    data = {
        "message": f"Update database - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "content": content,
        "sha": sha
    }
    requests.put(url, headers=headers, json=data)

def setup_github_sync():
    st.sidebar.subheader("GitHub Sync")
    if st.sidebar.button("📥 Download"):
        if download_db_from_github():
            st.rerun()
    if st.sidebar.button("📤 Upload"):
        upload_db_to_github()
    auto_sync = st.sidebar.checkbox("Auto-sync", value=False)
    return auto_sync

# --- Main App ---
def main():
    init_db()

    if "GITHUB_TOKEN" in st.secrets and "GITHUB_REPO" in st.secrets:
        st.session_state.auto_sync = setup_github_sync()
        if "github_init" not in st.session_state:
            download_db_from_github()
            st.session_state.github_init = True

    st.sidebar.title("🔧 Toolkit")
    page = st.sidebar.radio("Navigate:", [
        "Dashboard", "Links", "Passwords", "Files",
        "SQL Snippets", "Airflow DAGs", "Snowflake Configs",
        "Data Pipelines"
    ])

    if page == "Dashboard":
        st.title("📊 Dashboard")
        with get_connection() as conn:
            st.metric("Total Links", conn.execute("SELECT COUNT(*) FROM links").fetchone()[0])
            st.metric("Passwords", conn.execute("SELECT COUNT(*) FROM passwords").fetchone()[0])

    elif page == "Links":
        st.title("🔗 Links")
        with st.form("link_form"):
            title = st.text_input("Title")
            url = st.text_input("URL")
            if st.form_submit_button("Save"):
                execute_with_github_backup(
                    "INSERT INTO links (title, url, category, description, created_at) VALUES (?, ?, ?, ?, ?)",
                    (title, url, "General", "", datetime.now())
                )
                st.success("Saved!")
        with get_connection() as conn:
            links = conn.execute("SELECT * FROM links ORDER BY created_at DESC").fetchall()
            for link in links:
                st.write(f"[{link[1]}]({link[2]}) — {link[5]}")

    elif page == "Passwords":
        st.title("🔐 Passwords")
        with st.form("pw_form"):
            service = st.text_input("Service")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Save"):
                encrypted = encrypt_password(password)
                execute_with_github_backup(
                    "INSERT INTO passwords (service, username, password_encrypted, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                    (service, username, encrypted, "", datetime.now())
                )
                st.success("Password saved!")
        with get_connection() as conn:
            rows = conn.execute("SELECT * FROM passwords").fetchall()
            for row in rows:
                st.write(f"{row[1]} / {row[2]} — {decrypt_password(row[3])}")

    st.sidebar.markdown("---")
    st.sidebar.info("🔒 Passwords encrypted with Fernet")
    st.sidebar.info("💾 SQLite DB with GitHub backup")

if __name__ == "__main__":
    main()
