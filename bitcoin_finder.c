#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <gmp.h>
#include <secp256k1.h>
#include <time.h>

#define NUM_THREADS 4
#define CHUNK_SIZE 100000

typedef struct {
    mpz_t range_start;
    mpz_t range_end;
    int thread_id;
    unsigned long *checked;
    unsigned long *found;
    pthread_mutex_t *mutex;
    volatile int *found_complete;
} thread_args_t;

// Target public key hex
const char *TARGET_PUBKEY = "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673";

void hex_to_bytes(const char *hex, unsigned char *bytes, int len) {
    for (int i = 0; i < len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    }
}

void bytes_to_hex(unsigned char *bytes, int len, char *hex) {
    for (int i = 0; i < len; i++) {
        sprintf(hex + 2*i, "%02x", bytes[i]);
    }
    hex[2*len] = '\0';
}

// Fonction pour sauvegarder le résultat dans BINGO.TXT
void save_result(const char *privkey_hex, const char *pubkey_hex, int match_len) {
    FILE *file = fopen("BINGO.TXT", "w");
    if (file == NULL) {
        perror("Erreur: impossible de créer BINGO.TXT");
        return;
    }
    
    fprintf(file, "========================================\n");
    fprintf(file, "🎉 RÉSULTAT TROUVÉ!\n");
    fprintf(file, "========================================\n");
    fprintf(file, "Match Length: %d characters\n", match_len);
    fprintf(file, "Private Key: %s\n", privkey_hex);
    fprintf(file, "Public Key:  %s\n", pubkey_hex);
    fprintf(file, "Target:      %s\n", TARGET_PUBKEY);
    fprintf(file, "========================================\n");
    fprintf(file, "Timestamp: ");
    
    time_t now = time(NULL);
    fprintf(file, "%s", ctime(&now));
    fprintf(file, "========================================\n");
    
    fclose(file);
}

void *search_thread(void *args) {
    thread_args_t *targs = (thread_args_t *)args;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    
    mpz_t current;
    mpz_init_set(current, targs->range_start);
    
    unsigned long local_checked = 0;
    time_t start_time = time(NULL);
    
    // Recherche séquentielle dans la plage assignée
    while (mpz_cmp(current, targs->range_end) <= 0 && !*targs->found_complete) {
        // Convert mpz to bytes for secp256k1 (32 bytes = 256 bits)
        unsigned char privkey_bytes[32];
        memset(privkey_bytes, 0, 32);
        
        size_t count;
        mpz_export(privkey_bytes, &count, -1, 1, -1, 0, current);
        
        // Pad with zeros if needed (big-endian)
        if (count < 32) {
            memmove(privkey_bytes + (32 - count), privkey_bytes, count);
            memset(privkey_bytes, 0, 32 - count);
        }
        
        // Generate public key using secp256k1
        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_create(ctx, &pubkey, privkey_bytes)) {
            unsigned char pubkey_bytes[33];
            size_t pubkey_len = 33;
            secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);
            
            // Convert to hex
            char pubkey_hex[67];
            bytes_to_hex(pubkey_bytes, 33, pubkey_hex);
            
            // Check for prefix match
            int match_len = 0;
            for (int i = 0; i < 66 && TARGET_PUBKEY[i] && pubkey_hex[i]; i++) {
                if (TARGET_PUBKEY[i] == pubkey_hex[i]) {
                    match_len++;
                } else {
                    break;
                }
            }
            
            if (match_len >= 5) {
                char privkey_hex[65];
                bytes_to_hex(privkey_bytes, 32, privkey_hex);
                
                printf("✅ FOUND! Match Length: %d chars\n", match_len);
                printf("   Private Key: %s\n", privkey_hex);
                printf("   Public Key:  %s\n", pubkey_hex);
                printf("   Target:      %s\n", TARGET_PUBKEY);
                printf("   Matching:    %.*s\n\n", match_len, pubkey_hex);
                
                pthread_mutex_lock(targs->mutex);
                (*targs->found)++;
                
                // Si c'est une correspondance COMPLÈTE (66 caractères)
                if (match_len == 66) {
                    printf("🎉🎉🎉 CORRESPONDANCE COMPLÈTE TROUVÉE! 🎉🎉🎉\n");
                    save_result(privkey_hex, pubkey_hex, match_len);
                    *targs->found_complete = 1;
                    printf("\n✅ Résultat sauvegardé dans BINGO.TXT\n");
                }
                
                pthread_mutex_unlock(targs->mutex);
            }
        }
        
        // Incrémenter pour la clé suivante
        mpz_add_ui(current, current, 1);
        local_checked++;
        
        if (local_checked % CHUNK_SIZE == 0 && !*targs->found_complete) {
            pthread_mutex_lock(targs->mutex);
            *targs->checked += CHUNK_SIZE;
            time_t elapsed = time(NULL) - start_time;
            if (elapsed > 0) {
                double rate = *targs->checked / (double)elapsed;
                printf("⏱️  Thread %d: %lu keys checked | Speed: %.0f keys/sec | Time: %ld s\n", 
                       targs->thread_id, *targs->checked, rate, elapsed);
            }
            pthread_mutex_unlock(targs->mutex);
        }
    }
    
    secp256k1_context_destroy(ctx);
    mpz_clear(current);
    pthread_exit(NULL);
}

int main() {
    printf("🔍 Bitcoin Key Finder - C with GMP & secp256k1 (SEQUENTIAL SEARCH)\n");
    printf("========================================\n");
    printf("Target Public Key: %s\n", TARGET_PUBKEY);
    printf("Range: 0x8000000000000000000000000000000000000000 to 0xffffffffffffffffffffffffffffffffffffffff\n");
    printf("Search Mode: SEQUENTIAL (range divided per thread)\n");
    printf("Min Prefix Match: 5 characters\n");
    printf("Threads: %d\n", NUM_THREADS);
    printf("========================================\n\n");
    
    time_t start = time(NULL);
    
    // Initialize range - 160 bit Bitcoin private key range
    mpz_t range_start, range_end, range_size, chunk_size;
    mpz_init_set_str(range_start, "8000000000000000000000000000000000000000", 16);
    mpz_init_set_str(range_end, "ffffffffffffffffffffffffffffffffffffffff", 16);
    mpz_init(range_size);
    mpz_init(chunk_size);
    
    printf("Range start: ");
    mpz_out_str(stdout, 16, range_start);
    printf("\nRange end:   ");
    mpz_out_str(stdout, 16, range_end);
    printf("\n\n");
    
    // Calculer la taille de la plage totale
    mpz_sub(range_size, range_end, range_start);
    mpz_add_ui(range_size, range_size, 1);
    
    // Diviser la plage en chunks pour chaque thread
    mpz_cdiv_q_ui(chunk_size, range_size, NUM_THREADS);
    
    printf("Total range size: ");
    mpz_out_str(stdout, 16, range_size);
    printf("\nChunk size per thread: ");
    mpz_out_str(stdout, 16, chunk_size);
    printf("\n\n");
    
    pthread_t threads[NUM_THREADS];
    thread_args_t args[NUM_THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    unsigned long checked = 0, found = 0;
    volatile int found_complete = 0;
    
    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        mpz_init(args[i].range_start);
        mpz_init(args[i].range_end);
        
        // Calculer le début et la fin pour ce thread
        mpz_mul_ui(args[i].range_start, chunk_size, i);
        mpz_add(args[i].range_start, args[i].range_start, range_start);
        
        mpz_add(args[i].range_end, args[i].range_start, chunk_size);
        mpz_sub_ui(args[i].range_end, args[i].range_end, 1);
        
        // Le dernier thread va jusqu'à la fin
        if (i == NUM_THREADS - 1) {
            mpz_set(args[i].range_end, range_end);
        }
        
        args[i].thread_id = i;
        args[i].checked = &checked;
        args[i].found = &found;
        args[i].mutex = &mutex;
        args[i].found_complete = &found_complete;
        
        printf("Thread %d: Range from ", i);
        mpz_out_str(stdout, 16, args[i].range_start);
        printf(" to ");
        mpz_out_str(stdout, 16, args[i].range_end);
        printf("\n");
        
        pthread_create(&threads[i], NULL, search_thread, &args[i]);
    }
    
    printf("\n");
    
    // Wait for all threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    time_t elapsed = time(NULL) - start;
    
    printf("\n========================================\n");
    
    if (found_complete) {
        printf("🎉 🎉 🎉  SUCCÈS! 🎉 🎉 🎉\n");
        printf("========================================\n");
        printf("La clé COMPLÈTE a été trouvée!\n");
        printf("Les résultats ont été sauvegardés dans BINGO.TXT\n");
    } else {
        printf("🏁 Search Complete (range exhausted)\n");
    }
    
    printf("========================================\n");
    printf("Total Keys Checked: %lu\n", checked);
    printf("Total Matches Found (partial): %lu\n", found);
    if (elapsed > 0) {
        printf("Speed: %.0f keys/second\n", checked / (double)elapsed);
    }
    printf("Execution Time: %ld seconds\n", elapsed);
    printf("========================================\n");
    
    // Cleanup
    for (int i = 0; i < NUM_THREADS; i++) {
        mpz_clear(args[i].range_start);
        mpz_clear(args[i].range_end);
    }
    mpz_clear(range_start);
    mpz_clear(range_end);
    mpz_clear(range_size);
    mpz_clear(chunk_size);
    
    pthread_mutex_destroy(&mutex);
    
    return 0;
}
