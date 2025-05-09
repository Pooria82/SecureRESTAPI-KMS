import hvac
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import settings

client = hvac.Client(url=settings.vault_url, token=settings.vault_token)

def get_master_key():
    try:
        secret = client.secrets.kv.v2.read_secret_version(path='master_key')
        return bytes.fromhex(secret['data']['data']['key'])
    except hvac.exceptions.InvalidPath:
        master_key = AESGCM.generate_key(bit_length=256)
        client.secrets.kv.v2.create_or_update_secret(path='master_key', secret={'key': master_key.hex()})
        return master_key

def rotate_master_key():
    old_key = get_master_key()
    new_key = AESGCM.generate_key(bit_length=256)
    client.secrets.kv.v2.create_or_update_secret(path='master_key', secret={'key': new_key.hex()})
    return old_key, new_key

def generate_encryption_key():
    return AESGCM.generate_key(bit_length=256)

def store_user_key(username, key):
    master_key = get_master_key()
    aesgcm = AESGCM(master_key)
    nonce = secrets.token_bytes(12)
    encrypted_key = aesgcm.encrypt(nonce, key, None)
    client.secrets.kv.v2.create_or_update_secret(
        path=f'user_keys/{username}',
        secret={'key': encrypted_key.hex(), 'nonce': nonce.hex()}
    )

def get_user_key(username):
    try:
        secret = client.secrets.kv.v2.read_secret_version(path=f'user_keys/{username}')
        encrypted_key = bytes.fromhex(secret['data']['data']['key'])
        nonce = bytes.fromhex(secret['data']['data']['nonce'])
        master_key = get_master_key()
        aesgcm = AESGCM(master_key)
        return aesgcm.decrypt(nonce, encrypted_key, None)
    except hvac.exceptions.InvalidPath:
        raise ValueError("User key not found")

def encrypt_data(data, encryption_key):
    aesgcm = AESGCM(encryption_key)
    nonce = secrets.token_bytes(12)
    encrypted_data = aesgcm.encrypt(nonce, data.encode(), None)
    return nonce + encrypted_data

def decrypt_data(encrypted_data, encryption_key):
    aesgcm = AESGCM(encryption_key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()