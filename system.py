from user import User
from certificate import CertificateManager
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
import pickle
import linecache


class System:
    def __init__(self):
        self.registrated_users = []
        self.ca_path = linecache.getline("./path", 1).rstrip('\n')
        self.ca_key_path = linecache.getline("./path", 2).rstrip('\n')
        self.save_to_path = linecache.getline("./path", 3).rstrip('\n')
        self.reg_usr_path = linecache.getline("./path", 5).rstrip('\n')
        self.crl_path = linecache.getline("/path", 6).rstrip('\n')
        self.import_users()

    def import_users(self):
        try:
            with open(self.reg_usr_path, "rb") as file:
                self.registrated_users = pickle.load(file)
        except FileNotFoundError:
            print("Fajl registrovanih korisnika nije pronađen.")
        except EOFError:
            self.registrated_users = []

    def save_users(self):
        with open(self.reg_usr_path, "wb") as file:
            pickle.dump(self.registrated_users, file)

    def registeration(self, username, password, first_name, last_name, email, country, state, city):
        with open(self.ca_path, "rb") as ca_certificate_file:
            ca_certificate = x509.load_pem_x509_certificate(
                ca_certificate_file.read(),
                backend=default_backend()
            )
        if country != ca_certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value:
            print("Država mora da bude Bosna i Hercegovina(BA). Molimo pokušajte opet.")
            return False
        for user in self.registrated_users:
            if user.username == username:
                print("Korisničko ime je zauzeto. Molimo Vas izaberite drugo.")
                return False

        user = User(username, password, first_name, last_name, email, country, state, city)

        certificate = CertificateManager(self.ca_path, self.ca_key_path, self.crl_path)
        certificate.generate(user, password, self.save_to_path)

        self.registrated_users.append(user)
        self.save_users()

        print("Registracija uspješna!")
        print("Vaš PKI smješten je na: " + user.folder)
        return True

    def login(self, path, username, password):
        try:
            with open(path, 'rb') as cl_cert_file:
                pkcs12_cert = cl_cert_file.read()
                priv_key, cl_cert, _ = pkcs12.load_key_and_certificates(pkcs12_cert, password.encode(),
                                                                        default_backend())
        except FileNotFoundError:
            print("Vaš sertifikat nije pronađen na unesenoj putanji")
            return None, None, None, False
        except Exception as e:
            print("Greška: ", e)
            return None, None, None, False


        ca = CertificateManager(self.ca_path, self.ca_key_path, self.crl_path)
        if not ca.verify_certificate(cl_cert):
            return None, None, None, False

        public_key = cl_cert.public_key()

        for user in self.registrated_users:
            if username == user.username and user.verify_password(password):
                if username == cl_cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value:
                    return user, priv_key, public_key, True
                else:
                	print("Unijeli ste tuđi sertifikat! :( )")
                	return None, None, None, False        	
        print("Pogrešno korisničko ime ili lozinka.")
        return None, None, None, False
