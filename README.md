# Secure Data Encryption System

## Overview
The **Secure Data Encryption System** is a Python-based Streamlit application designed to securely store and retrieve sensitive data. It uses encryption and passkeys to ensure data confidentiality and includes mechanisms to prevent unauthorized access.

## Features
- **Master Password Protection**: Set a master password for securing access to the system.
- **Secure Data Storage**: Encrypt and store data with unique passkeys.
- **Data Retrieval**: Decrypt stored data using the corresponding passkey.
- **Security Measures**: Includes lockout functionality after multiple failed attempts.
- **Persistent Storage**: Saves encrypted data to a file for consistent access across sessions.

## How to Use
1. **Set Master Password**: On your first run, set a master password to secure the system.
2. **Login**: Enter the master password to access the application.
3. **Navigate**:
   - **Home**: Learn about the system's features and usage.
   - **Store Data**: Encrypt and save your data with a passkey.
   - **Retrieve Data**: Decrypt previously stored data by providing the encrypted text and passkey.
4. **Logout**: Use the logout option to secure your session.

## Security Notes
- Ensure you remember your master password; it is required for access.
- Use strong and unique passkeys for encrypting data.
