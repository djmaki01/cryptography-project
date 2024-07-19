import rsakey
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding


class CertificateManager:
    def __init__(self, ca_path, ca_key_path, crl_path):
        with open(ca_key_path, "rb") as ca_private_key_file:
            self.ca_private_key = serialization.load_pem_private_key(
                ca_private_key_file.read(),
                password=b"sigurnost",  # kljuc zasticen lozinkom sigurnost
                backend=default_backend()
            )

        # ucitava ca tijelo
        with open(ca_path, "rb") as ca_certificate_file:
            self.ca_certificate = x509.load_pem_x509_certificate(
                ca_certificate_file.read(),
                backend=default_backend()
            )
        self.crl_path = crl_path

    # generise sertifikat za korisnika(user)

    def verify_certificate(self, cl_cert):

        ca_public_key = self.ca_private_key.public_key()
        try:
            ca_public_key.verify(
                cl_cert.signature,
                cl_cert.tbs_certificate_bytes,
                asymmetric_padding.PKCS1v15(),
                cl_cert.signature_hash_algorithm,
            )
        except Exception as e:
            return False

        not_valid_before_utc_naive = cl_cert.not_valid_before_utc.replace(tzinfo=None)
        not_valid_after_utc_naive = cl_cert.not_valid_after_utc.replace(tzinfo=None)
        now = datetime.utcnow()
        if now < not_valid_before_utc_naive or now > not_valid_after_utc_naive:
            return False

        try:
            with open(self.crl_path, "rb") as crl_file:
                crl_data = crl_file.read()
                crl = x509.load_der_x509_crl(crl_data, default_backend())
        except FileNotFoundError:
            return True

        revoked_certificates = crl.revoked
        if revoked_certificates is not None:
            for revoked_certificate in revoked_certificates:
                if revoked_certificate.serial_number == cl_cert.serial_number:
                    print("Sertifikat povucen.")
                    return False

        return True

    def generate(self, user, password, save_to_path):
        # generise privatni kljuc
        priv_key = rsakey.generate(password.encode(), user.folder)

        # postavlja distinguished names za korisnika
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, user.country),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, user.state),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, user.city),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, user.first_name + " " + user.last_name),
            x509.NameAttribute(x509.NameOID.USER_ID, user.username)
        ])

        # kreira se sertifikat sa potrebnim podacima
        # critical - true: sistemi moraju razumjeti ekstenziju; false: mogu nastaviti s radom i ako je ne razumiju
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_certificate.subject
        ).public_key(
            priv_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(priv_key.public_key()),
            critical=False,
        )

        # potpisivanje koristenjem sha256
        certificate = builder.sign(
            private_key=self.ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # konertuje ga u PEM format
        certificate_pem = certificate.public_bytes(Encoding.PEM)

        # pkcs12
        pkcs12 = serialization.pkcs12.serialize_key_and_certificates(
            name=b"ime_necega_provjeri_kasnije",
            key=priv_key,
            cert=certificate,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )

        with open(save_to_path + "/" + user.username + "_cert.pem", "wb") as certificate_file:
            certificate_file.write(certificate_pem)

        # upisuje u fajl ./users/username/cert.pem
        with open(user.folder + "/cert.pfx", "wb") as certificate_file:
            certificate_file.write(pkcs12)

        return None
