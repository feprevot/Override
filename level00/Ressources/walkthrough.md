# Level00 — Walkthrough

## Analyse du binaire

Le binaire affiche un prompt `Password:`, lit un entier via `scanf`, puis compare cet entier à la constante `0x149c`.

```c
if (local_14[0] != 0x149c) {
    puts("\nInvalid Password!");
} else {
    puts("\nAuthenticated!");
    system("/bin/sh");
}
```

Si la valeur saisie est égale à `0x149c`, le programme exécute `/bin/sh` — ce qui nous donne un shell avec les droits de `level01` (le binaire est setuid).

## Conversion de la valeur attendue

`0x149c` en décimal :

```
0x149c = 1*16^3 + 4*16^2 + 9*16 + 12
       = 4096 + 1024 + 144 + 12
       = 5276
```

## Exploitation

Se connecter en SSH en tant que `level00`, puis :

```bash
./level00
# Password: 5276
# → Authenticated!
# $ cat /home/users/level01/.pass
# uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```

On lit ensuite le flag et on change d'utilisateur :

```bash
su level01
# Password: uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```

## Résumé

La vulnérabilité est triviale : le mot de passe est un entier codé en dur dans le binaire (`0x149c` = 5276). Il suffit de le convertir en décimal et de le saisir.
