# Secure File Vault

A Python-based secure file encryption application created for CSE439 Security Course at Yeditepe University. This application creates an encrypted container for storing sensitive files and provides strong encryption and secure authentication to protect files even if the physical drive is compromised.

## Features

### Security Features
- AES-256 encryption in CBC mode
- Password-based key derivation using PBKDF2
- Salted password hashing
- File integrity verification using SHA-256
- Secure temporary file handling
- No plaintext password storage

### Core Functionality
- **Vault Management**:
  - Create new secure vaults
  - Lock/unlock vaults with password authentication
  - Maintain encrypted container integrity
- **File Operations**:
  - Add files to vault with encryption
  - Extract files with automatic decryption
  - List stored files
  - Remove files from vault
  - Update existing files
- **Security Controls**:
  - Automatic vault locking
  - File integrity checking
  - Secure password validation

## Requirements

- Python 3.x
- Required Python packages:
  - pycryptodome
  - secrets
  - hashlib
  - pickle
  - base64

Install required packages using:
```bash
pip install pycryptodome
```

## Usage

### Running the Application
```bash
python SecureVault.py
```

### Menu Options

1. **Create Vault**
   - Creates a new encrypted vault
   - Sets up initial password protection
   - Initializes metadata storage

2. **Unlock Vault**
   - Authenticates user with password
   - Enables access to vault operations

3. **Add File**
   - Encrypts and stores new files in vault
   - Generates integrity checksums
   - Updates vault metadata

4. **List Files**
   - Shows all files stored in vault
   - Displays only filenames (no sensitive data)

5. **Extract File**
   - Decrypts and exports files
   - Verifies file integrity
   - Allows custom output location

6. **Remove File**
   - Securely removes files from vault
   - Updates vault structure
   - Maintains remaining files' integrity

7. **Update File**
   - Allows modification of existing files
   - Maintains encryption and integrity
   - Verifies changes before saving

8. **Lock Vault**
   - Secures vault access
   - Clears sensitive data from memory

0. **Exit**
   - Safely closes application
   - Ensures vault remains secured

## Security Implementation

### Encryption
- Uses AES-256 in CBC mode
- Unique initialization vector for each file
- Secure key derivation from password

### Password Protection
- PBKDF2 key derivation
- Salted password hashing
- Secure password comparison

### File Security
- Individual file encryption
- Integrity verification using SHA-256
- Secure temporary file handling

### Data Protection
- No plaintext password storage
- Encrypted metadata storage
- Secure memory handling

## File Structure

- `secure_vault.bin`: Encrypted container file
- `vault_metadata.pkl`: Encrypted metadata storage
- Temporary files handled securely

## Best Practices

1. **Password Selection**
   - Use strong, unique passwords
   - Avoid common phrases or patterns
   - Mix characters, numbers, and symbols

2. **File Management**
   - Keep backup of important files
   - Regular vault maintenance
   - Verify file integrity after operations

3. **Security Awareness**
   - Lock vault when not in use
   - Protect vault file location
   - Maintain system security

## Technical Details

### Encryption Process
1. Password-based key derivation (PBKDF2)
2. Salt generation for unique encryption
3. AES-256 encryption with CBC mode
4. Integrity hash generation
5. Secure storage in vault

### Decryption Process
1. Password validation
2. Key reconstruction
3. File integrity verification
4. Secure decryption
5. Safe file extraction

## Error Handling

- Invalid password protection
- File integrity verification
- Corruption detection
- Permission management
- Secure error reporting

## Contributing

This is a security-focused project. When contributing, please:
- Follow secure coding practices
- Maintain encryption standards
- Document security implications
- Test thoroughly

## Security Notice

This application is designed for educational purposes and personal use. While it implements strong security measures, no system is completely immune to all attacks. Always maintain proper security practices and keep sensitive data backed up securely.
