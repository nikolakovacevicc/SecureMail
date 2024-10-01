from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def sacuvaj_kljuc_u_pem(kljuc, fajl):
    with open(fajl, "wb") as f:
        f.write(kljuc)


def ucitaj_kljuc_iz_pem(fajl, lozinka=None):
    with open(fajl, "rb") as f:
        kljuc = f.read()

    if lozinka:
        privatni_kljuc = serialization.load_pem_private_key(
            kljuc,
            password=lozinka.encode(),
            backend=default_backend()
        )
        return privatni_kljuc
    else:
        javni_kljuc = serialization.load_pem_public_key(
            kljuc,
            backend=default_backend()
        )
        return javni_kljuc


def generisi_par(ime, email, velicinaKljuca, lozinka):
    privatni_kljuc = rsa.generate_private_key(public_exponent=65537, key_size=velicinaKljuca)
    javni_kljuc = privatni_kljuc.public_key()

    javni_pem = javni_kljuc.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    privatni_pem = privatni_kljuc.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(lozinka.encode())
    )

    #mora da se uzimaju poslednjih nzm koliko cifara ne ovako
    sacuvaj_kljuc_u_pem(javni_pem, f"{ime}_javni_kljuc.pem")
    sacuvaj_kljuc_u_pem(privatni_pem, f"{ime}_privatni_kljuc.pem")

    return javni_kljuc, privatni_kljuc


ime = "primer"
email = "primer@example.com"
velicinaKljuca = 2048
lozinka = "lozinka"

j, p = generisi_par(ime, email, velicinaKljuca, lozinka)

javni_kljuc_iz_fajla = ucitaj_kljuc_iz_pem(f"{ime}_javni_kljuc.pem")
privatni_kljuc_sa_lozinkom_iz_fajla = ucitaj_kljuc_iz_pem(f"{ime}_privatni_kljuc.pem", lozinka=lozinka)


def isti(a, b):
    if a == b:
        return True
    else:
        return False


print(p.private_numbers().d)
print(privatni_kljuc_sa_lozinkom_iz_fajla.private_numbers().d)
print(isti(p.private_numbers().d, privatni_kljuc_sa_lozinkom_iz_fajla.private_numbers().d))

print()

print(j.public_numbers().e)
print(javni_kljuc_iz_fajla.public_numbers().e)


