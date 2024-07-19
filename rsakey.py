from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# password za enkripciju kljuca
def generate(password, path):
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2046
    )

    # pkcs#8 format zasticen lozinkom
    encrypted_pem_private_key = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    # upisuje ga fajl i cuva na ./users/username/
    with open(path+"/encrypted_priv_key.pem", "wb") as private_key_file:
        private_key_file.write(encrypted_pem_private_key)

    return priv_key
