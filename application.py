from system import System
import getpass
import os
from profil import Profil
# from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes


class App:
    def __init__(self):
        self.system = System()

    def run(self):
        while True:
            os.system("cls" if os.name == "nt" else "clear")
            print("\n\nDOBRO DOŠLI!")
            print("____________________________________________________________________________\n")
            print("Izaberite opciju:\n")
            print("1 -> Prijava")
            print("2 -> Registracija\n\n")
            choice = input(">> ")
            print("\n\n")
            if choice == "1":
                print("Pokrećem prijavu...")
                input("Pritiniste Enter...")
                self.login_menu()
            elif choice == "2":
                print("Pokrećem registraciju...")
                input("Pritiniste Enter...")
                self.registration_menu()
            else:
                print("Pogrešan unos. Pokušajte ponovo.")
                input("Pritiniste Enter...")

    def login_menu(self):
        os.system("cls" if os.name == "nt" else "clear")
        print("\n\nPRIJAVA:")
        print("____________________________________________________________________________\n")
        path = input("Unesite putanju do Vašeg sertifikata: ")
        username = input("Unesi korisničko ime: ")
        password = getpass.getpass("Unesite lozinku: ")
        user, priv_key, public_key, success = self.system.login(path, username, password)
        if not success:
            print("\nPritisnite Enter da biste pokušali opet...")
            input()
        else:
            print("\n\nPrijava uspješna. Pritisnite Enter da nastavite dalje...")
            input()
            user_profil = Profil(user, password, public_key)
            self.generate_signature(user.file, priv_key)
            input("\n\n\nPress Enter to continue...")

    def registration_menu(self):
        os.system("cls" if os.name == "nt" else "clear")
        print("\n\nREGISTRACIJA:")
        print("Unesite sljedeće podatke:")
        print("____________________________________________________________________________\n")
        username = input("Korisničko ime (username): ")
        while True:
            password = getpass.getpass("Unesite lozinku: ")
            valid_pass = getpass.getpass("Potvrdite lozinku: ")
            if password != valid_pass:
                print("\nLozinke se ne poklapaju. Pokušajte opet.\n")
            else:
                break
        first_name = input("Ime: ")
        last_name = input("Prezime: ")
        email = input("e-mail: ")
        while True:
            country = input("Država [dvoslovna oznaka]: ")
            if len(country) != 2:
                print("\nNeispravan unos. Pokušajte ponovo.\n")
            else:
                break
        while True:
            state = input("Podlokalitet [dvoslovna oznaka]: ")
            if len(state) != 2:
                print("\nNeispravan unos. Pokušajte ponovo.\n")
            else:
                break
        city = input("Grad: ")
        print("\n")
        if not self.system.registeration(username, password, first_name, last_name, email, country, state, city):
            print("\n\nPritisnite Enter da biste pokušali opet...")
            input()
        else:
            input("\n\nPritisnite Enter da nastavite dalje...")

    def generate_signature(self, user_file, priv_key):

        try:
            with open(user_file, 'rb') as f:
                data = f.read()
        except EOFError:
            return

        signature = priv_key.sign(
            data,
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256()
        )

        with open(user_file + "signature", 'wb') as sign_file:
            sign_file.write(signature)


app = App()
app.run()
