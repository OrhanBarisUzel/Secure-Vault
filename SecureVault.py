import os
import hashlib
import secrets
import pickle
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import base64
import tempfile
import getpass

def load_metadata(metadata_file):
    if os.path.exists(metadata_file):
        try:
            with open(metadata_file, "rb") as meta_file:
                metadata= pickle.load(meta_file)
                salt_value = metadata.get("salt")
                if salt_value:
                    salt = base64.b64decode(salt_value)
                else:
                    salt = None
                password_hash= metadata.get("password_hash")
                return metadata, salt, password_hash
        except (pickle.PickleError, IOError):
            return {"files": []}, None, None
    return {"files": []}, None, None

def save_metadata(metadata_file, metadata, salt, password_hash):
    if salt:
        metadata["salt"]= base64.b64encode(salt).decode('utf-8')
    if password_hash:
        metadata["password_hash"]= password_hash
    with open(metadata_file, "wb") as meta_file:
        pickle.dump(metadata, meta_file)

def generate_salt():
    return secrets.token_bytes(16)

def derivation_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=100000)

def hash_password(password, salt):
    key= derivation_key(password, salt)
    hash_key= hashlib.sha256(key).hexdigest()
    return hash_key

def create_vault(vault_file, metadata_file, password):
    salt= generate_salt()
    password_hash= hash_password(password, salt)

    with open(vault_file, "wb") as vault:
        vault.write(b"")
    metadata= {"files": []}
    save_metadata(metadata_file, metadata, salt, password_hash)
    return metadata, salt, password_hash

def validate_password(password, salt, password_hash):
    if not salt or not password_hash:
        return False
    input_hash= hash_password(password, salt)
    return secrets.compare_digest(input_hash, password_hash)

def encrypt_file(vault_file, metadata, file_path, password, salt):
    if not validate_password(password, salt, metadata.get("password_hash")):
        raise ValueError("Incorrect password")

    file = open(file_path, "rb")
    try:
        file_data = file.read()
    finally:
        file.close()

    initialization_vector = secrets.token_bytes(16)
    key = derivation_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, initialization_vector)
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    file_hash = hashlib.sha256(file_data).hexdigest()

    vault = open(vault_file, "ab")
    try:
        vault.write(initialization_vector + encrypted_data)
    finally:
        vault.close()

    metadata["files"].append({
        "filename": os.path.basename(file_path),
        "encrypted_size": len(initialization_vector + encrypted_data),
        "hash": file_hash
    })

def decrypt_file(vault_file, metadata, filename, output_path, password, salt):
    if not validate_password(password, salt, metadata.get("password_hash")):
        raise ValueError("Incorrect password")
    key= derivation_key(password, salt)
    file_info= next((f for f in metadata["files"] if f["filename"]== filename), None)

    if not file_info:
        raise FileNotFoundError(f"File {filename} not found in vault")
    with open(vault_file, "rb") as vault:
        current_position= 0
        for metadata_file in metadata["files"]:
            if metadata_file["filename"]== filename:
                vault.seek(current_position)
                encrypted_data= vault.read(metadata_file["encrypted_size"])
                initialization_vector= encrypted_data[:16]
                encrypted_content= encrypted_data[16:]
                cipher= AES.new(key, AES.MODE_CBC, initialization_vector)
                decrypted_data= unpad(cipher.decrypt(encrypted_content), AES.block_size)
                decrypted_hash= hashlib.sha256(decrypted_data).hexdigest()
                
                if decrypted_hash != file_info["hash"]:
                    raise ValueError("File integrity check failed")
                with open(output_path, "wb") as output_file:
                    output_file.write(decrypted_data)
                return output_path
            current_position += metadata_file["encrypted_size"]
    raise FileNotFoundError(f"File {filename} not found in vault")

def list_files(metadata):
    return [f["filename"] for f in metadata["files"]]

def remove_file(vault_file, metadata, filename, password, salt):
    if not validate_password(password, salt, metadata.get("password_hash")):
        raise ValueError("Incorrect password")
    new_vault_data= []
    new_metadata_files= []

    with open(vault_file, "rb") as vault:
        for file_info in metadata["files"]:
            encrypted_data = vault.read(file_info["encrypted_size"])
            if file_info["filename"]!= filename:
                new_vault_data.append(encrypted_data)
                new_metadata_files.append(file_info)

    with open(vault_file, "wb") as vault:
        for data in new_vault_data:
            vault.write(data)
    metadata["files"] = new_metadata_files

def update_file(vault_file, metadata, filename, password, salt):
    if not validate_password(password, salt, metadata.get("password_hash")):
        raise ValueError("Incorrect password")
    file_info= next((f for f in metadata["files"] if f["filename"]== filename), None)
    if not file_info:
        raise FileNotFoundError(f"File {filename} not found in vault")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file_path= os.path.join(temp_dir, filename)
        decrypt_file(vault_file, metadata, filename, temp_file_path, password, salt)
        print(f"File extracted to temporary path: {temp_file_path}")
        os.startfile(temp_file_path)
        update= input("Do you want to update it? Type yes, else no: ").strip().lower()
        if update== "yes":
            with open(temp_file_path, "rb") as edited_file:
                edited_content= edited_file.read()
            original_hash= file_info["hash"]
            edited_hash= hashlib.sha256(edited_content).hexdigest()

            if edited_hash== original_hash:
                print("No changes detected in the file. Update skipped.")
                return

            remove_file(vault_file, metadata, filename, password, salt)
            encrypt_file(vault_file, metadata, temp_file_path, password, salt)
            print(f"File '{filename}' has been updated in the vault.")
        else:
            print("File update canceled.")

def main():
    base_dir= os.path.dirname(os.path.abspath(__file__))
    vault_file= os.path.join(base_dir, "secure_vault.bin")
    metadata_file= os.path.join(base_dir, "vault_metadata.pkl")
    metadata, salt, password_hash= load_metadata(metadata_file)
    is_vault_unlocked= False
    password= None
    print("\nSecure File Vault    ")
    while True:
        print("Press")
        print("1 to Create Vault")
        print("2 to Unlock Vault")
        print("3 to Add File")
        print("4 to List Files")
        print("5 to Extract File")
        print("6 to Remove File")
        print("7 to Update File")
        print("8 to Lock Vault")
        print("0 to Exit")

        option= input("Choose an option: ").strip()

        try:
            if option== "1":
                password= input("Enter a new password: ").strip()
                metadata, salt, password_hash= create_vault(vault_file, metadata_file, password)
                print("Vault created!")

            elif option== "2":
                password= getpass.getpass("Enter your password: ")
                if validate_password(password, salt, password_hash):
                    is_vault_unlocked= True
                    print("Vault unlocked successfully!")
                else:
                    print("Incorrect password.")

            elif option== "3":
                if not is_vault_unlocked:
                    raise PermissionError("Unlock the vault first.")
                file_path= input("Enter the path of the file to add: ").strip()
                encrypt_file(vault_file, metadata, file_path, password, salt)
                save_metadata(metadata_file, metadata, salt, password_hash)
                print(f"File '{os.path.basename(file_path)}' added.")

            elif option== "4":
                if not is_vault_unlocked:
                    raise PermissionError("Unlock the vault first.")
                files= list_files(metadata)
                print("\nFiles in vault:")
                for i, file in enumerate(files, 1):
                    print(f"{i}. {file}")
                print("\n")

            elif option== "5":
                if not is_vault_unlocked:
                    raise PermissionError("Unlock the vault first.")
                filename= input("Enter the name of the file to extract: ").strip()
                output_path= input("Enter the output path (If you want to save pin project directory please leave blank): ").strip()
                if not output_path:
                    output_path= os.path.join(base_dir, filename)
                decrypt_file(vault_file, metadata, filename, output_path, password, salt)
                print(f"File '{filename}' extracted to {output_path}.")

            elif option== "6":
                if not is_vault_unlocked:
                    raise PermissionError("Unlock the vault first.")
                filename= input("Enter the name of the file to remove: ").strip()
                remove_file(vault_file, metadata, filename, password, salt)
                save_metadata(metadata_file, metadata, salt, password_hash)
                print(f"File '{filename}' removed.")

            elif option== "7":
                if not is_vault_unlocked:
                    raise PermissionError("Unlock the vault first.")
                filename= input("Enter the name of the file to update: ").strip()
                update_file(vault_file, metadata, filename, password, salt)
                save_metadata(metadata_file, metadata, salt, password_hash)

            elif option== "8":
                is_vault_unlocked= False
                password= None
                print("Vault locked.")

            elif option== "0":
                print("Exiting. Goodbye!")
                return 0

            else:
                print("The option you have chose is invalid. Try again.")
        except PermissionError as pe:
            print(f"Error: {str(pe)}")
        except Exception as e:
            print(f"Error: {str(e)}")
    


if __name__== "__main__":
    main()