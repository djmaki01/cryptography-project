# from user import User
import os
import myszkowski
import railfence
import playfair
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import base64


class Profil:
    def __init__(self, user, password, public_key):
        self.user = user
        self.password = password
        self.public_key = public_key
        self.header()
        self.verify_signature()
        self.run()

    def header(self):
        os.system("cls" if os.name == "nt" else "clear")
        print(f"{self.user.username}, DOBRO DOŠLI!")
        print("______________________________________________________________________________\n")

    def run(self):
        while True:
            print("Odaberite:\n")
            print("1 - PREGLED ISTORIJE")
            print("2 - SIMULACIJA KRIPTOGRAFSKIH ALGORITAMA\n\n\n")
            print("______________________________________________________________________________\n")
            print("3 - ODJAVA")
            option = input("\n\nVaš izbor je: ")
            if option == "1":
                self.header()
                self.file_review()
                input("\n\n\nPress Enter to continue....")
            elif option == "2":
                self.simulation()
                input("\n\n\nPress Enter to continue....")
            elif option == "3":
                break
            else:
                print("Pogrešan unos.")
                input("Pritisnite Enter da pokušate opet...")
            self.header()

    def verify_signature(self):
        try:
            with open(self.user.file, 'rb') as data_file:
                data = data_file.read()
        except EOFError:
            print("Još niste izvršili nijednu simulaciju.")

        try:
            with open(self.user.file + "signature", 'rb') as sign_data:
                signature = sign_data.read()
        except FileNotFoundError:
            print("Još niste izvršili nijednu simulaciju.")
            return
        try:
            self.public_key.verify(
                signature,
                data,
                asymmetric_padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            print(f"\nVaš fajl na lokaciji: {self.user.file} je kompromitovan!\n")

    def file_review(self):
        try:
            with open(self.user.file, 'rb') as data_file:
                encrypted_data = data_file.read()
                if not encrypted_data:
                    print("Istorija je prazna.")
                    return None
            with open(self.user.file, 'rb') as data_file:
                for line in data_file:
                    encrypted_line = line.rstrip(b'\n')
                    decrypted_line = self.decrypt(encrypted_line)
                    if decrypted_line:
                        print(decrypted_line)
        except FileNotFoundError:
            print("Fajl nije pronadjen.")

    def simulation(self):
        while True:
            self.header()
            print("Dostupni algoritmi:")
            print("    1 - MYSZKOWSKI")
            print("    2 - RAILFENCE")
            print("    3 - PLAYFAIR\n\n")
            alg = input("Vaš izbor je: ")
            if alg == "1":
                print("Unesite tekst koji želite enkriptovati (max. 100 karaktera): ")
                text = input("TEKST: ")
                if len(text) > 100:
                    text = text[:100]
                key = input("Ključ: ")
                cipher = myszkowski.encrypt(key, text)
                encrypted_data = self.encrypt_simulation(text.upper(), "MYSZKOWSKI", key.upper(), cipher.upper())
                break
            elif alg == "2":
                while True:
                    try:
                        print("Unesite tekst koji želite enkriptovati (max. 100 karaktera): ")
                        text = input("TEKST: ")
                        if len(text) > 100:
                            text = text[:100]
                        rails = input("Broj kolosjeka: ")
                        cipher = railfence.encrypt(int(rails), text)
                        encrypted_data = self.encrypt_simulation(text.upper(), "RAILFENCE", str(rails), cipher.upper())
                        break
                    except ValueError:
                        print("\nUnos mora biti broj.")
                        input("\n\nPress Enter to continue...") 
                break
            elif alg == "3":
                print("Unesite tekst koji želite enkriptovati (max. 100 karaktera): ")
                text = input("TEKST: ")
                if len(text) > 100:
                    text = text[:100]
                key = input("Ključ: ")
                cipher = playfair.encrypt(key, text)
                encrypted_data = self.encrypt_simulation(text.upper(), "PLAYFAIR", key.upper(), cipher.upper())
                break
            else:
                print("Pogrešan unos. Pritisnite Enter da pokušate ponovo...")
                input()

        print("\nŠIFRAT: ", cipher)
        self.save_simulation(encrypted_data)

    def decrypt(self, encrypted_data):
        try:
            password = self.password.encode()
            salt = self.user.username.encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=1000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
        except Exception as e:
            print("Dekripcija nije uspjela.")
            return None
        return decrypted_data.decode()

    def encrypt_simulation(self, text, alg, key, cipher):
        plaintext = text + "|" + alg + "|" + key + "|" + cipher
        password = self.password.encode()
        salt = self.user.username.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        encrypted_data = f.encrypt(plaintext.encode())
        return encrypted_data

    def save_simulation(self, encrypted_data):
        with open(self.user.file, 'ab') as f:
            f.write(encrypted_data + b'\n')
