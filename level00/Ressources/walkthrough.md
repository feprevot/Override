# Level00 — Walkthrough

**Objectif :** le binaire compare l'entier saisi à une constante hardcodée. On lit la constante dans le code désassemblé, on la convertit en décimal, et on la saisit pour obtenir un shell.

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
0x149c = 5276
```

## Résumé

La vulnérabilité est simple : le mot de passe est un entier codé en dur dans le binaire (`0x149c` = 5276). Il suffit de le convertir en décimal et de le saisir.
