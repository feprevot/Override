# Walkthrough — level03

## 1. Analyse du source

Le binaire demande un entier et enchaîne trois fonctions :

1. `get_unum()` lit un entier non signé via `scanf("%u")`.
2. `test(value, 0x1337d00d)` calcule `key = 0x1337d00d - value` puis appelle `decrypt(key)` si `key` est dans la liste `{1..9, 16..21}`, sinon `decrypt(rand())`.
3. `decrypt(key)` XOR le tableau chiffré octet par octet avec `key`, puis compare le résultat à `"Congratulations!"` via `memcmp`. Si égal → `system("/bin/sh")`.

---

## 2. Identifier la constante fixe avec Ghidra

Dans Ghidra, juste avant le `CALL test` dans `main` :

```
080488ca  MOV dword ptr [ESP+4], 0x1337d00d   ← param_2 (constante fixe)
080488d2  MOV dword ptr [ESP],   EAX           ← param_1 (valeur saisie)
080488d5  CALL test
```

La constante est donc **`0x1337d00d`** (322 424 845 en décimal).

---

## 3. Identifier la bonne clé

`decrypt()` contient ce tableau d'octets :
```
0x51, 0x7d, 0x7c, 0x75, 0x60, 0x73, 0x66, 0x67,
0x7e, 0x73, 0x66, 0x7b, 0x7d, 0x7c, 0x61, 0x33
```

On cherche quelle `key` transforme le premier octet en `'C'` (= `0x43`) :
```
0x51 XOR key = 0x43
key = 0x51 XOR 0x43 = 0x12
```

On vérifie avec Python :
```bash
python -c "
buf = [0x51, 0x7d, 0x7c, 0x75, 0x60, 0x73, 0x66, 0x67,
       0x7e, 0x73, 0x66, 0x7b, 0x7d, 0x7c, 0x61, 0x33]
print(''.join(chr(b ^ 0x12) for b in buf))
"
```
Sortie : `Congratulations!` — la bonne clé est bien **`0x12`** (18 en décimal).

---

## 4. Exploitation

`key = constante - value`, on veut `key = 0x12` :

```
value = 0x1337d00d - 0x12 = 0x1337cffb
```

En décimal :
```bash
python -c "print(0x1337d00d - 0x12)"
# → 322424827
```

On lance le binaire et on entre ce nombre :
```bash
./level03
# Password: 322424827
# Congratulations!
# $ cat /home/users/level04/.pass
```

---

## 5. Résumé de la faille

| Élément          | Détail                                              |
|-----------------|------------------------------------------------------|
| Type            | Logique de validation faible                         |
| Ligne faillible | `key = param_2 - param_1` dans `test()`              |
| Condition       | `key == 0x12` est dans les cas autorisés du switch   |
| Technique       | Calcul arithmétique : `value = constante - 0x12`     |
| Mot de passe    | `322424827`                                          |
