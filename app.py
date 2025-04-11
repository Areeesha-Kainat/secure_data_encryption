import streamlit as st
import hashlib
import time
from cryptography.fernet import Fernet
import base64
from streamlit_extras.stylable_container import stylable_container

# Custom CSS for enhanced styling
def inject_custom_css():
    st.markdown("""
    <style>
        :root {
            --primary: #4361ee;
            --secondary: #3a0ca3;
            --accent: #7209b7;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #4bb543;
            --warning: #ffcc00;
            --danger: #ff3333;
        }
        
        .main {
            background: linear-gradient(135deg, #f5f7fa 0%, #e4e8f0 100%);
        }
        
        .stApp {
            background: transparent;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            margin-bottom: 1.5rem;
            border: 1px solid rgba(0,0,0,0.05);
        }
        
        .card-header {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--secondary);
            margin-bottom: 1.5rem;
            position: relative;
            padding-bottom: 0.5rem;
        }
        
        .card-header:after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 0;
            width: 50px;
            height: 3px;
            background: var(--accent);
            border-radius: 3px;
        }
        
        .input-field {
            margin-bottom: 1.5rem;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            border: none;
            padding: 0.5rem 1.5rem;
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(67, 97, 238, 0.3);
        }
        
        .sidebar .sidebar-content {
            background: linear-gradient(180deg, var(--secondary) 0%, var(--accent) 100%);
            color: white;
        }
        
        .sidebar .nav-item {
            padding: 0.75rem 1rem;
            margin: 0.25rem 0;
            border-radius: 8px;
            transition: all 0.3s ease;
        }
        
        .sidebar .nav-item:hover {
            background: rgba(255,255,255,0.15);
        }
        
        .sidebar .nav-item.active {
            background: rgba(255,255,255,0.25);
            font-weight: 600;
        }
        
        .lock-icon {
            font-size: 2rem;
            color: var(--accent);
            margin-bottom: 1rem;
        }
        
        .encrypted-display {
            background: var(--dark);
            color: #00ff9d;
            font-family: monospace;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.9rem;
            margin-top: 1rem;
        }
        
        .attempt-counter {
            font-size: 0.85rem;
            color: var(--danger);
            margin-top: 0.5rem;
        }
        
        .success-message {
            background: rgba(75, 181, 67, 0.1);
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid var(--success);
            margin: 1rem 0;
        }
        
        .error-message {
            background: rgba(255, 51, 51, 0.1);
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid var(--danger);
            margin: 1rem 0;
        }
        
        .warning-message {
            background: rgba(255, 204, 0, 0.1);
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid var(--warning);
            margin: 1rem 0;
        }
        
        .password-strength {
            height: 4px;
            background: #e9ecef;
            border-radius: 2px;
            margin-top: 0.25rem;
            overflow: hidden;
        }
        
        .password-strength-bar {
            height: 100%;
            transition: all 0.3s ease;
        }
        
        .weak {
            background: var(--danger);
            width: 30%;
        }
        
        .medium {
            background: var(--warning);
            width: 60%;
        }
        
        .strong {
            background: var(--success);
            width: 100%;
        }
    </style>
    """, unsafe_allow_html=True)

# Password strength indicator function
def password_strength(passkey):
    if not passkey:
        return ""
    length = len(passkey)
    has_upper = any(c.isupper() for c in passkey)
    has_lower = any(c.islower() for c in passkey)
    has_digit = any(c.isdigit() for c in passkey)
    has_special = any(not c.isalnum() for c in passkey)

    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if has_upper:
        score += 1
    if has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1

    if score <= 2:
        return "weak"
    elif score <= 4:
        return "medium"
    else:
        return "strong"

# Setup session state for encryption key and storage
if "cipher" not in st.session_state:
    KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(KEY)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Flag to force admin login (do not tie to sidebar widget key)
if "force_admin" not in st.session_state:
    st.session_state.force_admin = False

cipher = st.session_state.cipher

# Utility functions
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text: str) -> str:
    encrypted = cipher.encrypt(text.encode())
    return base64.urlsafe_b64encode(encrypted).decode()

def decrypt_data(encrypted_text: str) -> str:
    encrypted = base64.urlsafe_b64decode(encrypted_text.encode())
    return cipher.decrypt(encrypted).decode()

# UI Setup
st.set_page_config(
    page_title="Quantum Vault",
    layout="centered",
    page_icon="🔒"
)

inject_custom_css()

# Sidebar navigation
with st.sidebar:
    st.markdown("""
    <div style="padding: 1rem; margin-bottom: 2rem;">
        <h2 style="color: white; margin-bottom: 0;">Quantum Vault</h2>
        <p style="color: rgba(255,255,255,0.8); font-size: 0.9rem;">Military-grade data encryption</p>
    </div>
    """, unsafe_allow_html=True)
    
    nav_options = {
        "Home": "home",
        "Store Data": "store",
        "Retrieve Data": "retrieve",
        "Admin Access": "login"
    }
    
    # Warn user if a forced admin authorization is needed
    if st.session_state.force_admin:
        st.warning("Too many failed attempts. Please select 'Admin Access' in the sidebar to reauthorize.")
    
    selected = st.radio("Navigation", list(nav_options.keys()), key="nav", label_visibility="collapsed")

# Home Page
if nav_options[selected] == "home":
    with stylable_container(key="home_container", css_styles="text-align: center; padding: 2rem 1rem;"):
        st.markdown("""
        <div class="lock-icon">🔒</div>
        <h1 style="color: var(--secondary); margin-bottom: 1rem;">Quantum Vault</h1>
        <p style="color: var(--dark); font-size: 1.1rem;">
            Ultra-secure data storage with end-to-end encryption. Your secrets are safe with us.
        </p>
        """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        with stylable_container(key="feature1", css_styles="padding: 1.5rem; background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);"):
            st.markdown("""
            <h3 style="color: var(--primary);">Military-Grade</h3>
            <p>AES-256 encryption that meets government security standards</p>
            """, unsafe_allow_html=True)
    with col2:
        with stylable_container(key="feature2", css_styles="padding: 1.5rem; background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);"):
            st.markdown("""
            <h3 style="color: var(--primary);">Zero-Knowledge</h3>
            <p>We never store or see your encryption keys or passwords</p>
            """, unsafe_allow_html=True)
    with col3:
        with stylable_container(key="feature3", css_styles="padding: 1.5rem; background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);"):
            st.markdown("""
            <h3 style="color: var(--primary);">Secure Storage</h3>
            <p>Data is encrypted before it leaves your device</p>
            """, unsafe_allow_html=True)

# Store Data Page
elif nav_options[selected] == "store":
    with stylable_container(key="store_container", css_styles="padding: 2rem;"):
        st.markdown("""
        <div class="card">
            <div class="card-header">Encrypt Your Data</div>
            <p>Store sensitive information securely. Your data will be encrypted before storage.</p>
        """, unsafe_allow_html=True)
        
        user_text = st.text_area("Enter your confidential data", height=150, key="user_text",
                                 help="This could be passwords, API keys, or any sensitive information")
        passkey = st.text_input("Create a strong passkey", type="password", key="store_passkey",
                                help="You'll need this passkey to decrypt your data later")
        
        if passkey:
            strength = password_strength(passkey)
            st.markdown(f"""
            <div class="password-strength">
                <div class="password-strength-bar {strength}"></div>
            </div>
            <small>Password strength: <strong>{strength.capitalize()}</strong></small>
            """, unsafe_allow_html=True)
        
        if st.button("Encrypt & Store", key="encrypt_btn", use_container_width=True):
            if user_text and passkey:
                hashed = hash_passkey(passkey)
                encrypted = encrypt_data(user_text)
                st.session_state.stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
                st.markdown("""
                <div class="success-message">
                    Your data has been securely encrypted and stored.
                </div>
                """, unsafe_allow_html=True)
                st.markdown(f"""
                <p><strong>Your encrypted data:</strong></p>
                <div class="encrypted-display">
                    {encrypted}
                </div>
                <p class="small">Copy this encrypted text for future retrieval.</p>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="error-message">
                    Both data and passkey fields are required for encryption.
                </div>
                """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

# Retrieve Data Page
elif nav_options[selected] == "retrieve":
    with stylable_container(key="retrieve_container", css_styles="padding: 2rem;"):
        st.markdown("""
        <div class="card">
            <div class="card-header">Decrypt Your Data</div>
            <p>Retrieve your encrypted information using your passkey.</p>
        """, unsafe_allow_html=True)
        
        encrypted_input = st.text_area("Paste your encrypted data", height=100, key="encrypted_input")
        passkey = st.text_input("Enter your passkey", type="password", key="retrieve_passkey")
        
        if st.button("Decrypt", key="decrypt_btn", use_container_width=True):
            if encrypted_input and passkey:
                hashed_input = hash_passkey(passkey)
                stored_item = st.session_state.stored_data.get(encrypted_input)
                if stored_item and stored_item["passkey"] == hashed_input:
                    try:
                        decrypted_text = decrypt_data(encrypted_input)
                        st.markdown("""
                        <div class="success-message">
                            Data decrypted successfully!
                        </div>
                        """, unsafe_allow_html=True)
                        st.text_area("Decrypted Content", decrypted_text, height=200, key="decrypted_output")
                        st.session_state.failed_attempts = 0
                    except Exception:
                        st.markdown("""
                        <div class="error-message">
                            Invalid encrypted data format.
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.session_state.failed_attempts += 1
                    remaining = 3 - st.session_state.failed_attempts
                    st.markdown(f"""
                    <div class="error-message">
                        Incorrect passkey! Attempts remaining: {remaining}
                    </div>
                    """, unsafe_allow_html=True)
                    if st.session_state.failed_attempts >= 3:
                        st.markdown("""
                        <div class="warning-message">
                            Too many failed attempts. Please navigate to 'Admin Access' to reauthorize.
                        </div>
                        """, unsafe_allow_html=True)
                        st.session_state.force_admin = True
                        st.stop()
            else:
                st.markdown("""
                <div class="error-message">
                    Both encrypted data and passkey are required for decryption.
                </div>
                """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

# Admin Access (Login) Page
elif nav_options[selected] == "login":
    with stylable_container(key="login_container", css_styles="padding: 2rem;"):
        st.markdown("""
        <div class="card">
            <div class="card-header">Admin Authentication</div>
            <p>Enter admin credentials to reset failed attempts.</p>
        </div>
        """, unsafe_allow_html=True)
        master_pass = st.text_input("Admin Password", type="password", key="admin_pass")
        if st.button("Authenticate", key="auth_btn", use_container_width=True):
            if master_pass == "admin123":
                st.session_state.failed_attempts = 0
                st.session_state.force_admin = False
                st.markdown("""
                <div class="success-message">
                    Authentication successful. Please proceed to the 'Retrieve Data' page.
                </div>
                """, unsafe_allow_html=True)
                time.sleep(1)
            else:
                st.markdown("""
                <div class="error-message">
                    Incorrect admin password. Please try again.
                </div>
                """, unsafe_allow_html=True)
