import streamlit as st
import sqlite3
import pandas as pd
import json
import base64
import hashlib
import requests
import os
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime
import snowflake.connector

# =====================
# Page configuration
# =====================
st.set_page_config(
    page_title="Data Engineer's Notes App",
    page_icon="📊",
    layout="wide"
)

# =====================
# Encryption setup (robust)
# Accepts either a Fernet key (44-char urlsafe base64) or a passphrase in secrets
# =====================
def _derive_fernet_key_from_passphrase(passphrase: str) -> bytes:
    # Deterministic 32-byte key -> urlsafe_b64encode for Fernet
    digest = hashlib.sha256(passphrase.encode()).digest()  # 32 bytes
    return base64.urlsafe_b64encode(digest)

@st.cache_resource(show_spinner=False)
def get_cipher_suite() -> Fernet:
    key_raw = st.secrets.get("ENCRYPTION_KEY")
    key: bytes
    if key_raw:
        # Try to use as a Fernet key first
        try:
            candidate = key_raw.encode() if isinstance(key_raw, str) else key_raw
            # quick validation: attempt to build Fernet
            Fernet(candidate)
            key = candidate
        except Exception:
            # Treat as passphrase; derive Fernet key
            key = _derive_fernet_key_from_passphrase(str(key_raw))
            st.info("Derived Fernet key from passphrase in secrets.")
    else:
        # Generate ephemeral key for dev
        key = Fernet.generate_key()
        st.warning("⚠️ ENCRYPTION_KEY missing in secrets. Using a temporary key (passwords won't decrypt across sessions).")
    return Fernet(key)

cipher_suite = get_cipher_suite()

# =====================
# Database Helpers (no global/stored connection)
# =====================

def get_connection():
    # Allow cross-thread usage by creating short-lived connections per use
    return sqlite3.connect("data_engineer_notes.db", check_same_thread=False)

def run_snowflake_query(config, query):
    try:
        conn = snowflake.connector.connect(
            user=config["user"],
            password=config["password"],
            account=config["account"],
            warehouse=config.get("warehouse"),
            database=config.get("database"),
            authenticator='https://intusurg.okta.com/okta/sso/saml',
            schema=config.get("schema"),
            role=config.get("role"),
        )
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        conn.close()
        return columns, rows
    except Exception as e:
        st.error(f"❌ Snowflake execution failed: {e}")
        return None, None


@st.cache_resource(show_spinner=False)
def _ensure_schema_once() -> None:
    with get_connection() as conn:
        c = conn.cursor()
        # Links
        c.execute('''CREATE TABLE IF NOT EXISTS links
                     (id INTEGER PRIMARY KEY, title TEXT, url TEXT, category TEXT,
                      description TEXT, created_at TIMESTAMP)''')
        # Passwords
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                     (id INTEGER PRIMARY KEY, service TEXT, username TEXT,
                      password_encrypted BLOB, notes TEXT, created_at TIMESTAMP)''')
        # Files metadata
        c.execute('''CREATE TABLE IF NOT EXISTS files
                     (id INTEGER PRIMARY KEY, filename TEXT, file_type TEXT,
                      description TEXT, tags TEXT, created_at TIMESTAMP)''')
        # SQL snippets
        c.execute('''CREATE TABLE IF NOT EXISTS sql_snippets
                     (id INTEGER PRIMARY KEY, title TEXT, sql_code TEXT,
                      database_type TEXT, description TEXT, tags TEXT, created_at TIMESTAMP)''')
        # Airflow DAGs
        c.execute('''CREATE TABLE IF NOT EXISTS airflow_dags
                     (id INTEGER PRIMARY KEY, dag_name TEXT, description TEXT,
                      schedule TEXT, owner TEXT, tags TEXT, created_at TIMESTAMP)''')
        # Snowflake configs
        c.execute('''CREATE TABLE  IF NOT EXISTS snowflake_configs
                     (id INTEGER PRIMARY KEY, config_name TEXT, account_url TEXT, warehouse TEXT, user TEXT, password BLOB,
                     database TEXT, schema TEXT, role TEXT, notes TEXT, created_at TIMESTAMP)''')
        # Data pipelines
        c.execute('''CREATE TABLE IF NOT EXISTS data_pipelines
                     (id INTEGER PRIMARY KEY, pipeline_name TEXT, description TEXT,
                      source TEXT, destination TEXT, transformation_logic TEXT,
                      schedule TEXT, owner TEXT, tags TEXT, created_at TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS todos 
                    (id INTEGER PRIMARY KEY, title TEXT, description TEXT, priority TEXT, due_date DATE, status TEXT, created_at TIMESTAMP)''')
        
        conn.commit()

# Helper to run write queries + optional GitHub backup

def execute_with_github_backup(query: str, params: tuple | None = None):
    with get_connection() as conn:
        if params:
            conn.execute(query, params)
        else:
            conn.execute(query)
        conn.commit()
    if st.session_state.get('auto_sync', False):
        upload_db_to_github()

# =====================
# Encryption helpers
# =====================

def encrypt_password(password: str) -> bytes:
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password: bytes) -> str:
    try:
        return cipher_suite.decrypt(encrypted_password).decode()
    except (InvalidToken, TypeError):
        return "<Unable to decrypt with current key>"

# =====================
# GitHub integration
# =====================

def get_github_auth_headers():
    token = st.secrets.get("GITHUB_TOKEN")
    if not token:
        return None
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

def download_db_from_github(show_toast=True) -> bool:
    repo = st.secrets.get("GITHUB_REPO")
    if not repo:
        if show_toast:
            st.sidebar.warning("GitHub repository not configured (GITHUB_REPO).")
        return False
    headers = get_github_auth_headers()
    if not headers:
        if show_toast:
            st.sidebar.error("GitHub token not found (GITHUB_TOKEN).")
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
                if show_toast:
                    st.sidebar.success("Database downloaded from GitHub.")
                return True
        elif response.status_code == 404:
            if show_toast:
                st.sidebar.info("No DB on GitHub yet. It will be created locally.")
            return True
        else:
            if show_toast:
                st.sidebar.error(f"Download failed: {response.status_code}")
            return False
    except Exception as e:
        if show_toast:
            st.sidebar.error(f"Error downloading DB: {e}")
        return False

def upload_db_to_github() -> bool:
    repo = st.secrets.get("GITHUB_REPO")
    if not repo:
        st.sidebar.warning("GITHUB_REPO not configured.")
        return False
    headers = get_github_auth_headers()
    if not headers:
        st.sidebar.error("GITHUB_TOKEN not found.")
        return False

    url = f"https://api.github.com/repos/{repo}/contents/data_engineer_notes.db"
    try:
        # Get SHA if file exists
        r = requests.get(url, headers=headers)
        sha = r.json().get("sha") if r.status_code == 200 else None
        # Read file
        with open("data_engineer_notes.db", "rb") as f:
            content = base64.b64encode(f.read()).decode("utf-8")
        data = {
            "message": f"Update DB - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "content": content,
            "sha": sha
        }
        put = requests.put(url, headers=headers, json=data)
        if put.status_code in (200, 201):
            st.sidebar.success("Database uploaded to GitHub.")
            return True
        else:
            msg = put.json().get("message", put.text)
            st.sidebar.error(f"Upload failed: {msg}")
            return False
    except Exception as e:
        st.sidebar.error(f"Error uploading DB: {e}")
        return False

# Sidebar GitHub controls

def setup_github_sync():
    st.sidebar.subheader("GitHub Sync")
    if st.sidebar.button("📥 Download from GitHub"):
        if download_db_from_github():
            st.rerun()
    if st.sidebar.button("📤 Upload to GitHub"):
        upload_db_to_github()
    auto = st.sidebar.checkbox("Auto-sync with GitHub", value=False)
    return auto

# =====================
# App Initialization
# =====================

def init_app():
    # If GitHub is configured, attempt download first so we migrate schema on that file
    if "GITHUB_TOKEN" in st.secrets and "GITHUB_REPO" in st.secrets:
        if "github_init" not in st.session_state:
            download_db_from_github(show_toast=True)
            st.session_state.github_init = True
        st.session_state.auto_sync = setup_github_sync()
    else:
        st.sidebar.info("GitHub not configured. Add GITHUB_TOKEN and GITHUB_REPO to secrets.toml")

    # Ensure schema exists
    _ensure_schema_once()

# =====================
# UI Pages
# =====================

def page_dashboard():
    st.title("📊 Naresh's Dashboard")
    with get_connection() as conn:
        c = conn.cursor()
        counts = {
            'links': c.execute("SELECT COUNT(*) FROM links").fetchone()[0],
            'sql_snippets': c.execute("SELECT COUNT(*) FROM sql_snippets").fetchone()[0],
            'airflow_dags': c.execute("SELECT COUNT(*) FROM airflow_dags").fetchone()[0],
            'files': c.execute("SELECT COUNT(*) FROM files").fetchone()[0],
            'snowflake_configs': c.execute("SELECT COUNT(*) FROM snowflake_configs").fetchone()[0],
            'passwords': c.execute("SELECT COUNT(*) FROM passwords").fetchone()[0],
            'data_pipelines': c.execute("SELECT COUNT(*) FROM data_pipelines").fetchone()[0],
            'to_do': c.execute("SELECT COUNT(*) FROM todos").fetchone()[0],
        }
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Links", counts['links'])
        st.metric("SQL Snippets", counts['sql_snippets'])
    with col2:
        st.metric("Airflow DAGs", counts['airflow_dags'])
        st.metric("Files Stored", counts['files'])
    with col3:
        st.metric("Snowflake Configs", counts['snowflake_configs'])
        st.metric("Passwords", counts['passwords'])
    with col4:
        st.metric("Data Pipelines", counts['data_pipelines'])
        st.metric("GitHub Sync", "✅" if st.session_state.get('auto_sync', False) else "❌")
    with col5:
        st.metric("To Do List", counts['to_do'])
    # Recent activity
    st.subheader("Recent Activity")
    recent_activities = []
    with get_connection() as conn:
        c = conn.cursor()
        for table in ['links', 'sql_snippets', 'airflow_dags', 'files', 'data_pipelines']:
            items = c.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 3").fetchall()
            for item in items:
                title = item[1] if len(item) > 1 else table
                ts = item[-1] if len(item) > 0 else None
                recent_activities.append({'type': table, 'title': title, 'timestamp': ts})
    for activity in sorted(recent_activities, key=lambda x: x['timestamp'] or '', reverse=True)[:5]:
        st.write(f"📅 {activity['timestamp']} - {activity['type'].title()}: {activity['title']}")


def page_links():
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
        with get_connection() as conn:
            links = conn.execute("SELECT * FROM links ORDER BY created_at DESC").fetchall()
        for link in links:
            with st.expander(f"{link[1]} ({link[3]})"):
                st.write(f"**URL:** [{link[2]}]({link[2]})")
                st.write(f"**Description:** {link[4]}")
                st.write(f"**Created:** {link[5]}")
                if st.button("Delete", key=f"del_link_{link[0]}"):
                    execute_with_github_backup("DELETE FROM links WHERE id = ?", (link[0],))
                    st.rerun()


def page_passwords():
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
        with get_connection() as conn:
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


def page_files():
    st.title("📁 File Storage")
    uploaded_file = st.file_uploader("Upload a file", type=[
        'py', 'sql', 'json', 'yaml', 'yml', 'txt', 'csv', 'md',
        'ipynb', 'xml', 'conf', 'cfg', 'ini', 'zip'
    ])

    if uploaded_file is not None:
        file_type = uploaded_file.type
        description = st.text_input("File description")
        tags = st.text_input("Tags (comma-separated)")
        if st.button("Save File Metadata"):
            execute_with_github_backup(
                "INSERT INTO files (filename, file_type, description, tags, created_at) VALUES (?, ?, ?, ?, ?)",
                (uploaded_file.name, file_type, description, tags, datetime.now())
            )
            st.success("File metadata saved!")

    st.subheader("Stored Files")
    with get_connection() as conn:
        files = conn.execute("SELECT * FROM files ORDER BY created_at DESC").fetchall()
    for file in files:
        with st.expander(f"{file[1]} ({file[2]})"):
            st.write(f"**Description:** {file[3]}")
            st.write(f"**Tags:** {file[4]}")
            st.write(f"**Created:** {file[5]}")
            if st.button("Delete", key=f"del_file_{file[0]}"):
                execute_with_github_backup("DELETE FROM files WHERE id = ?", (file[0],))
                st.rerun()


def page_sql_snippets():
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
        with get_connection() as conn:
            snippets = conn.execute("SELECT * FROM sql_snippets ORDER BY created_at DESC").fetchall()
        for snippet in snippets:
            with st.expander(f"{snippet[1]} ({snippet[3]})"):
                st.code(snippet[2], language='sql')
                st.write(f"**Description:** {snippet[4]}")
                st.write(f"**Tags:** {snippet[5]}")
                st.write(f"**Created:** {snippet[6]}")
                st.markdown(f"**{snippet[1]}**  \nCategory: {snippet[3]}  \n{snippet[4]}")

                # If this is a Snowflake snippet
                if snippet[3].lower() == "snowflake":
                    # Load saved configs
                    with get_connection() as conn:
                        configs = conn.execute("SELECT id, config_name, account_url, user, password, warehouse, database, schema, role FROM snowflake_configs").fetchall()
                    if configs:
                        config_options = {f"{c[1]} ({c[2]})": c for c in configs}
                        selected = st.selectbox("Select Snowflake Config", list(config_options.keys()), key=f"cfg_{snippet[0]}")
                        if st.button("Run on Snowflake", key=f"run_{snippet[0]}"):
                            cfg = config_options[selected]
                            config_dict = {
                                "name": cfg[1],
                                "account": cfg[2],
                                "user": cfg[3],
                                "password": cfg[4],
                                "warehouse": cfg[5],
                                "database": cfg[6],
                                "schema": cfg[7],
                                "role": cfg[8],
                            }
                            cols, rows = run_snowflake_query(config_dict, snippet[2])  # row[2] is snippet text
                            if cols and rows:
                                st.dataframe(pd.DataFrame(rows, columns=cols))
                if st.button("Delete", key=f"del_sql_{snippet[0]}"):
                    execute_with_github_backup("DELETE FROM sql_snippets WHERE id = ?", (snippet[0],))
                    st.rerun()



def page_airflow_dags():
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
        with get_connection() as conn:
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

def to_do() :
    st.title("📝 To-Do List")
    
    tab1, tab2 = st.tabs(["Add Task", "View Tasks"])
    
    with tab1:
        with st.form("todo_form"):
            title = st.text_input("Title")
            description = st.text_area("Description")
            priority = st.selectbox("Priority", ["Low", "Medium", "High"])
            due_date = st.date_input("Due Date")
            status = st.selectbox("Status", ["Pending", "In Progress", "Completed"])
            
            if st.form_submit_button("Add Task"):
                with get_connection() as conn:
                    conn.execute('''
                        INSERT INTO todos (title, description, priority, due_date, status, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (title, description, priority, due_date, status, datetime.now(datetime.UTC)))
                    conn.commit()
                st.success("Task added!")

    with tab2:
        with get_connection() as conn:
            tasks = conn.execute("SELECT * FROM todos ORDER BY due_date ASC").fetchall()
        
        for task in tasks:
            st.write(f"**{task[1]}** [{task[5]}] - Due: {task[4]}")
            with st.expander('', expanded=True):
                st.markdown(task[2])
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Mark Completed", key=f"done_{task[0]}"):
                    with get_connection() as conn:
                        conn.execute("UPDATE todos SET status='Completed' WHERE id=?", (task[0],))
                        conn.commit()
                    st.rerun()
            with col2:
                if st.button("Delete", key=f"del_{task[0]}"):
                    with get_connection() as conn:
                        conn.execute("DELETE FROM todos WHERE id=?", (task[0],))
                        conn.commit()
                    st.rerun()


def page_snowflake_configs():
    st.title("❄️ Snowflake Configurations")
    tab1, tab2 = st.tabs(["Add Config", "View Configs"])

    with tab1:
        with st.form("snowflake_form"):
            config_name = st.text_input("Configuration Name")
            account_url = st.text_input("Account URL", placeholder="https://your-account.snowflakecomputing.com")
            warehouse = st.text_input("Warehouse", value="COMPUTE_WH")
            user = st.text_input("User Name")
            password = st.text_input("Password", type="password")
            database = st.text_input("Database")
            schema = st.text_input("Schema", value="PUBLIC")
            role = st.text_input("Role", value="SYSADMIN")
            notes = st.text_area("Notes")
            if st.form_submit_button("Save Configuration"):
                encrypted_pw = encrypt_password(password)
                execute_with_github_backup(
                    "INSERT INTO snowflake_configs (config_name, account_url, warehouse, user, password, database, schema, role, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (config_name, account_url, warehouse, user, password, database, schema, role, notes, datetime.now())
                )
                st.success("Snowflake configuration saved!")

    with tab2:
        with get_connection() as conn:
            configs = conn.execute("SELECT * FROM snowflake_configs ORDER BY created_at DESC").fetchall()
        for config in configs:
            with st.expander(f"{config[1]}"):
                decrypted_pw = decrypt_password(config[5])
                st.write(f"**Account URL:** {config}")
                st.write(f"**Warehouse:** {config[3]}")
                st.write(f"**User Name:** {config[4]}")
                st.write(f"**Password:** {config[5]}")
                st.write(f"**Database:** {config[6]}")
                st.write(f"**Schema:** {config[7]}")
                st.write(f"**Role:** {config[8]}")
                st.write(f"**Notes:** {config[9]}")
                st.write(f"**Created:** {config[10]}")
                if st.button("Delete", key=f"del_snow_{config[0]}"):
                    execute_with_github_backup("DELETE FROM snowflake_configs WHERE id = ?", (config[0],))
                    st.rerun()


def page_data_pipelines():
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
        with get_connection() as conn:
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

# =====================
# Main
# =====================

def main():
    init_app()

    st.sidebar.title("🔧 Data Engineer's Toolkit")
    page = st.sidebar.radio("Navigate to:", [
        "Dashboard", "To Do List", "Links", "Passwords", "Files",
        "SQL Snippets", "Airflow DAGs", "Snowflake Configs",
        "Data Pipelines"
    ])

    if page == "Dashboard":
        page_dashboard()
    elif page == "To Do List" :
        to_do()
    elif page == "Links":
        page_links()
    elif page == "Passwords":
        page_passwords()
    elif page == "Files":
        page_files()
    elif page == "SQL Snippets":
        page_sql_snippets()
    elif page == "Airflow DAGs":
        page_airflow_dags()
    elif page == "Snowflake Configs":
        page_snowflake_configs()
    elif page == "Data Pipelines":
        page_data_pipelines()

    st.sidebar.markdown("---")
    st.sidebar.info("🔒 Passwords are encrypted with Fernet (stable key or passphrase in secrets)")
    st.sidebar.info("💾 Data stored in SQLite and can sync with GitHub")


if __name__ == "__main__":
    main()
