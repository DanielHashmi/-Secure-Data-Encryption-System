import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64

def load_verification_token():
    try:
        with open("verification_token.txt", "r") as f:
            return f.read()
    except FileNotFoundError:
        return None

def save_verification_token(token):
    with open("verification_token.txt", "w") as f:
        f.write(token)

verification_token = load_verification_token()
if verification_token is None:
    st.title("🔐 Set Master Password")
    master_password = st.text_input("Create Master Password:", type="password")
    if st.button("Set Password"):
        if master_password:
            key = hashlib.sha256(master_password.encode()).digest()
            cipher_key = base64.urlsafe_b64encode(key)
            cipher = Fernet(cipher_key)
            verification_token = cipher.encrypt(b"MASTER_PASSWORD_VERIFICATION").decode()
            save_verification_token(verification_token)
            st.session_state.cipher_key = cipher_key
            st.session_state.cipher = cipher
            st.session_state.master_password_hash = hashlib.sha256(master_password.encode()).hexdigest()
            st.success("✅ Master password set successfully!")
            time.sleep(1)
            st.rerun()
        else:
            st.error("⚠️ Please enter a password.")
else:
    if 'cipher_key' not in st.session_state:
        st.title("🔐 Enter Master Password")
        master_password = st.text_input("Master Password:", type="password")
        if st.button("Login"):
            if master_password:
                key = hashlib.sha256(master_password.encode()).digest()
                cipher_key = base64.urlsafe_b64encode(key)
                cipher = Fernet(cipher_key)
                try:
                    decrypted = cipher.decrypt(verification_token.encode()).decode()
                except:
                    decrypted = ''
                    
                if decrypted == "MASTER_PASSWORD_VERIFICATION":
                    st.session_state.cipher_key = cipher_key
                    st.session_state.cipher = cipher
                    st.session_state.master_password_hash = hashlib.sha256(master_password.encode()).hexdigest()
                    st.success("✅ Logged in successfully!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Incorrect master password!")
            else:
                st.error("⚠️ Please enter the password.")
    else:
        if 'stored_data' not in st.session_state:
            st.session_state.stored_data = {}
        if 'failed_attempts' not in st.session_state:
            st.session_state.failed_attempts = 0
        if 'last_failed_time' not in st.session_state:
            st.session_state.last_failed_time = 0

        def hash_passkey(passkey):
            return hashlib.sha256(passkey.encode()).hexdigest()

        def encrypt_data(text):
            return st.session_state.cipher.encrypt(text.encode()).decode()

        def decrypt_data(encrypted_text, passkey):
            hashed_passkey = hash_passkey(passkey)
            entry = st.session_state.stored_data.get(encrypted_text)
            if entry and entry["passkey"] == hashed_passkey:
                st.session_state.failed_attempts = 0
                return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
            
            if st.session_state.failed_attempts < 3:
                st.session_state.failed_attempts += 1
                if st.session_state.failed_attempts == 3:
                    st.session_state.last_failed_time = time.time()
            return None

        def is_locked_out():
            if st.session_state.failed_attempts >= 3:
                if time.time() - st.session_state.last_failed_time < 30:
                    return True
            return False

        def save_data_to_file():
            try:
                with open("encrypted_data.json", "w") as f:
                    json.dump(st.session_state.stored_data, f)
                return True
            except Exception as e:
                st.error(f"Error saving data: {e}")
                return False

        def load_data_from_file():
            try:
                with open("encrypted_data.json", "r") as f:
                    st.session_state.stored_data = json.load(f)
                return True
            except FileNotFoundError:
                return True
            except Exception as e:
                st.error(f"Error loading data: {e}")
                return False

        load_data_from_file()

        st.title("🔒 Secure Data Encryption System")
        menu = ["Home", "Store Data", "Retrieve Data"]
        choice = st.sidebar.selectbox("Navigation", menu)
        
        if is_locked_out() and choice != "Login":
            st.warning("🔒 You are locked out due to too many failed attempts. Please reauthorize.")
            choice = "Login"

        if choice == "Home":
            st.subheader("🏠 Welcome to the Secure Data System")
            st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
            st.markdown("""
            ### Features
            - **Store data securely** with unique passkeys
            - **Retrieve data** using your passkey
            - **Security measures** to prevent unauthorized access
            - **Persistent storage** across sessions with file backup

            ### How to Use
            1. Go to 'Store Data' to encrypt and save your information
            2. Use 'Retrieve Data' to access your stored information
            3. If you enter an incorrect passkey too many times, reauthorize via 'Login'
            """)

        elif choice == "Store Data":
            st.subheader("📂 Store Data Securely")
            data_label = st.text_input("Data Label (optional):", help="Name your data for easy identification")
            user_data = st.text_area("Enter Data to Encrypt:")
            passkey = st.text_input("Create Passkey:", type="password", help="Use a strong, memorable passkey")
            confirm_passkey = st.text_input("Confirm Passkey:", type="password")
            if st.button("Encrypt & Save"):
                if user_data and passkey:
                    if passkey != confirm_passkey:
                        st.error("⚠️ Passkeys don't match!")
                    else:
                        hashed_passkey = hash_passkey(passkey)
                        encrypted_text = encrypt_data(user_data)
                        label = data_label if data_label else f"Data_{len(st.session_state.stored_data) + 1}"
                        st.session_state.stored_data[encrypted_text] = {
                            "passkey": hashed_passkey,
                            "label": label,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        save_data_to_file()
                        st.success("✅ Data stored securely!")
                        st.code(encrypted_text, language="text")
                        st.info("👆 Copy this encrypted text to retrieve your data later.")
                else:
                    st.error("⚠️ Both data and passkey are required!")

        elif choice == "Retrieve Data":
            st.subheader("🔍 Retrieve Your Data")
            if not st.session_state.stored_data:
                st.warning("No encrypted data found. Please store some data first.")
            else:
                retrieval_method = st.radio("Retrieval Method", ["Select from stored data", "Enter encrypted text manually"])
                if retrieval_method == "Select from stored data":
                    options = [f"{value.get('label', 'Unnamed Data')} ({value.get('timestamp', 'Unknown time')})"
                               for value in st.session_state.stored_data.values()]
                    if options:
                        selected_option = st.selectbox("Select data to decrypt:", options)
                        selected_index = options.index(selected_option)
                        encrypted_text = list(st.session_state.stored_data.keys())[selected_index]
                    else:
                        st.warning("No data available to select.")
                        encrypted_text = ""
                else:
                    encrypted_text = st.text_area("Enter Encrypted Data:")
                passkey = st.text_input("Enter Passkey:", type="password")
                if st.button("Decrypt"):
                    if encrypted_text and passkey:
                        decrypted_text = decrypt_data(encrypted_text, passkey)
                        if decrypted_text:
                            st.success("✅ Decryption successful!")
                            st.markdown("### Decrypted Data:")
                            st.code(decrypted_text, language="text")
                        else:
                            remaining = max(3 - st.session_state.failed_attempts, 0)
                            st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                            if st.session_state.failed_attempts >= 3:
                                st.warning("🔒 Too many failed attempts! Locked out for 30 seconds or until reauthorization.")
                                time.sleep(1)
                                st.rerun()
                    else:
                        st.error("⚠️ Both encrypted data and passkey are required!")

        elif choice == "Login" and st.session_state.failed_attempts >= 3:
            st.subheader("🔑 Reauthorization Required")
            st.write("Reauthorize to continue after too many failed attempts.")
            login_pass = st.text_input("Enter Master Password:", type="password")
            if st.button("Login"):
                if hashlib.sha256(login_pass.encode()).hexdigest() == st.session_state.master_password_hash:
                    st.session_state.failed_attempts = 0
                    st.success("✅ Reauthorized successfully!")
                    st.info("Logging In Again...")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Incorrect master password!")

        st.sidebar.markdown("---")
        st.sidebar.subheader("System Status")
        st.sidebar.write(f"📊 Stored data items: {len(st.session_state.stored_data)}")
        st.sidebar.write(f"🔑 Failed attempts: {st.session_state.failed_attempts}/3")
        st.sidebar.write("🔒 Status: Locked" if is_locked_out() else "🔓 Status: Unlocked")
        
        if st.sidebar.button("Logout"):
            for key in st.session_state.keys():
                del st.session_state[key]
            st.rerun()
