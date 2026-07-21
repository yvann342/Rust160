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

// Fonction pour générer un nombre aléatoire dans une plage
void generate_random_in_range(mpz_t result, mpz_t range_start, mpz_t range_end) {
    mpz_t range_size;
    mpz_init(range_size);
    
    // Calculer la taille de la plage: range_end - range_start + 1
    mpz_sub(range_size, range_end, range_start);
    mpz_add_ui(range_size, range_size, 1);
    
    // Générer un nombre aléatoire jusqu'à la taille de la plage
    mpz_t random;
    mpz_init(random);
    
    // Utiliser /dev/urandom pour plus d'aléatoire
    FILE *fp = fopen("/dev/urandom", "r");
    unsigned char random_bytes[32];
    fread(random_bytes, 1, 32, fp);
    fclose(fp);
    
    mpz_import(random, 32, -1, 1, -1, 0, random_bytes);
    mpz_mod(random, random, range_size);
    
    // result = range_start + random
    mpz_add(result, range_start, random);
    
    mpz_clear(random);
    mpz_clear(range_size);
}

void *search_thread(void *args) {
    thread_args_t *targs = (thread_args_t *)args;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    
    mpz_t current;
    mpz_init(current);
    
    unsigned long local_checked = 0;
    time_t start_time = time(NULL);
    
    // Recherche aléatoire infinie
    while (1) {
        // Générer un nombre aléatoire dans la plage
        generate_random_in_range(current, targs->range_start, targs->range_end);
        
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
                pthread_mutex_unlock(targs->mutex);
            }
        }
        
        local_checked++;
        
        if (local_checked % CHUNK_SIZE == 0) {
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
    printf("🔍 Bitcoin Key Finder - C with GMP & secp256k1 (RANDOM SEARCH)\n");
    printf("========================================\n");
    printf("Target Public Key: %s\n", TARGET_PUBKEY);
    printf("Range: 0x8000000000000000000000000000000000000000 to 0xffffffffffffffffffffffffffffffffffffffff\n");
    printf("Search Mode: COMPLETELY RANDOM\n");
    printf("Min Prefix Match: 5 characters\n");
    printf("Threads: %d\n", NUM_THREADS);
    printf("========================================\n\n");
    
    time_t start = time(NULL);
    
    // Initialize range - 160 bit Bitcoin private key range
    mpz_t range_start, range_end;
    mpz_init_set_str(range_start, "8000000000000000000000000000000000000000", 16);
    mpz_init_set_str(range_end, "ffffffffffffffffffffffffffffffffffffffff", 16);
    
    printf("Range start: ");
    mpz_out_str(stdout, 16, range_start);
    printf("\nRange end:   ");
    mpz_out_str(stdout, 16, range_end);
    printf("\n\n");
    
    pthread_t threads[NUM_THREADS];
    thread_args_t args[NUM_THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    unsigned long checked = 0, found = 0;
    
    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        mpz_init_set(args[i].range_start, range_start);
        mpz_init_set(args[i].range_end, range_end);
        
        args[i].thread_id = i;
        args[i].checked = &checked;
        args[i].found = &found;
        args[i].mutex = &mutex;
        
        printf("Thread %d: Starting with random search in range\n", i);
        
        pthread_create(&threads[i], NULL, search_thread, &args[i]);
    }
    
    printf("\n");
    
    // Wait for all threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    time_t elapsed = time(NULL) - start;
    
    printf("\n========================================\n");
    printf("🏁 Search Complete!\n");
    printf("========================================\n");
    printf("Total Keys Checked: %lu\n", checked);
    printf("Total Matches Found: %lu\n", found);
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
    
    pthread_mutex_destroy(&mutex);
    
    return 0;
}
