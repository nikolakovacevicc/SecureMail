import rsa

public_key, private_key = rsa.newkeys(1024)
print(public_key)
print(private_key)

with open("public.pem", "wb") as f:
    f.write(public_key.save_pkcs1("PEM"))

with open("private.pem", "wb") as f:
    f.write(private_key.save_pkcs1("PEM"))


with open("public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

#sifrovanje poruke
message = "neka poruka"

encrypted = rsa.encrypt(message.encode(), public_key)

with open("encrypted.message", "wb") as f:
    f.write(encrypted)

message_encrypted = open("encrypted.message", "rb").read()
decrypted = rsa.decrypt(message_encrypted, private_key)

print(decrypted.decode())


#potpisivanje poruke
message = "Nova poruka koju zelimo da potpisemo privatnim kljucem"
message2 = "Nije potpisana kako treba"

signature = rsa.sign(message.encode(), private_key, "SHA-256")

with open("signature", "wb") as f:
    f.write(signature)

signature_encrypted = open("signature", "rb").read()
decrypted = rsa.verify(message.encode(), signature_encrypted, public_key)

print(decrypted)
