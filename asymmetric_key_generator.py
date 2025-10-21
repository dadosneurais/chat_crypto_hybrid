from Crypto.Util.number import getPrime

# complexidade de 2048 bits
p=getPrime(1024)
q=getPrime(1024)


# geração de chaves
def generate_keys():
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)

pub, priv = generate_keys()

# save
with open('server_public_key.txt', 'w') as f:
    f.write(f"{pub[0]},{pub[1]}")

with open('server_private_key.txt', 'w') as f:
    f.write(f"{priv[0]},{priv[1]}")