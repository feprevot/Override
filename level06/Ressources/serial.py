login = "qordoux"

if len(login) < 6:
    print("Login trop court (min 6 chars)")
    exit(1)

hash_val = (ord(login[3]) ^ 0x1337) + 0x5eeded

for c in login:
    hash_val += (ord(c) ^ hash_val) % 0x539

serial = hash_val & 0xFFFFFFFF  # tronque à 32 bits : Python n'a pas d'overflow, le C oui

print(f"Login:  {login}")
print(f"Serial: {serial}")
