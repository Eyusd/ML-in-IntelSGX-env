from Crypto.PublicKey import RSA

key = RSA.generate(2048)
with open("client_rsa_pubkey.pem", 'wb') as f:
    f.write(key.publickey().exportKey('PEM', pkcs=1))
f.close()
print(len(key.publickey().exportKey('PEM', pkcs=1)))