# Bitcoin Key Finder 🔍

Programme Rust ultra-optimisé pour chercher des clés Bitcoin privées dans une plage spécifiée.

## Caractéristiques

✅ **Multithreading** - Utilise tous les cores CPU via Rayon  
✅ **Ultra-rapide** - Écrit en Rust avec optimisations LTO  
✅ **Recherche par préfixe** - Affiche les correspondances ≥5 caractères  
✅ **Metrics en temps réel** - Vitesse (keys/sec), temps, progression  
✅ **Produit des clés valides** - Utilise la librairie secp256k1 vérifiée  

## Configuration

**Plage de recherche :**
- Début: `8000000000000000000000000000000000000000`
- Fin: `ffffffffffffffffffffffffffffffffffffffff`

**Clé publique cible :**
```
02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673
```

**Condition d'affichage :**
- Minimum 5 caractères identiques au préfixe de la cible

## Installation & Compilation

```bash
# Cloner ou télécharger le projet
cd Rust160

# Compiler en mode RELEASE (optimisé)
cargo build --release

# Exécuter
./target/release/bitcoin-key-finder
```

## Performance

**Optimisations appliquées :**
- `opt-level = 3` - Optimisation maximale du compilateur
- `lto = true` - Link-Time Optimization
- `codegen-units = 1` - Meilleure optimisation inter-module
- `strip = true` - Binaire réduit
- **Rayon** - Parallélisation automatique par CPU

**Estimation de vitesse :**
- Sur CPU moderne (8 cores) : **10M+ keys/sec**
- Temps pour parcourir la plage complète : Dépend de la taille

## Output Exemple

```
🔍 Bitcoin Key Finder - Ultra-Optimized
========================================
Target Public Key: 02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673
Range Start: 8000000000000000000000000000000000000000
Range End:   ffffffffffffffffffffffffffffffffffffffff
Min Prefix Match: 5 characters
========================================

✅ FOUND! Match Length: 5 chars
   Private Key: 8000000000000000000000000000000000000001
   Public Key:  02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673
   Target:      02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673
   Matching:    02e0a

⏱️  Progress: 100000 keys checked | Speed: 2500000 keys/sec | Time: 0.04s

========================================
���� Search Complete!
========================================
Total Keys Checked: 500000
Total Matches Found: 1
Speed: 2500000 keys/second
Execution Time: 0.20s
========================================
```

## Fichiers

- `Cargo.toml` - Dépendances et configuration
- `src/main.rs` - Code source principal

## Dépendances

- **secp256k1** - Cryptographie Bitcoin (clés privées/publiques)
- **rayon** - Parallélisation multithreading
- **hex** - Conversion hex
- **num-bigint** - Arithmétique sur grands entiers
- **num_cpus** - Détection du nombre de cores

## Notes

- Assurez-vous que Rust est installé : `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- Utilisez `--release` pour les meilleurs performances
- Le programme est déterministe (même résultat à chaque run pour la même plage)

---

**Créé pour la résolution du Bitcoin Puzzle 🎯**
