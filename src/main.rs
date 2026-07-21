use hex::FromHex;
use num_bigint::BigUint;
use rayon::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let start = Instant::now();

    // Target public key
    let target_pubkey_hex = "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673";
    let target_pubkey_bytes =
        Vec::<u8>::from_hex(target_pubkey_hex).expect("Invalid hex target pubkey");

    // Range: 8000000000000000000000000000000000000000:ffffffffffffffffffffffffffffffffffffffff
    let start_range = BigUint::from_bytes_be(
        &Vec::<u8>::from_hex("8000000000000000000000000000000000000000").unwrap(),
    );
    let end_range = BigUint::from_bytes_be(
        &Vec::<u8>::from_hex("ffffffffffffffffffffffffffffffffffffffff").unwrap(),
    );

    println!("🔍 Bitcoin Key Finder - Ultra-Optimized");
    println!("========================================");
    println!("Target Public Key: {}", target_pubkey_hex);
    println!("Range Start: 8000000000000000000000000000000000000000");
    println!("Range End:   ffffffffffffffffffffffffffffffffffffffff");
    println!("Min Prefix Match: 5 characters");
    println!("Threads: {}", num_cpus::get());
    println!("========================================\n");

    let secp = Secp256k1::new();
    let found_count = Arc::new(AtomicUsize::new(0));
    let checked_count = Arc::new(AtomicUsize::new(0));
    let chunk_size = 1_000_000;

    // Split range into chunks for parallel processing
    let num_chunks = num_cpus::get();
    let range_size = &end_range - &start_range;
    let chunk_range = &range_size / num_chunks as u32;

    (0..num_chunks)
        .par_bridge()
        .for_each(|chunk_idx| {
            let chunk_start = &start_range + (&chunk_range * chunk_idx as u32);
            let chunk_end = if chunk_idx == num_chunks - 1 {
                end_range.clone()
            } else {
                &start_range + (&chunk_range * (chunk_idx as u32 + 1))
            };

            let mut current = chunk_start;
            let secp = Secp256k1::new();

            while current <= chunk_end {
                // Convert BigUint to 32-byte private key
                let key_bytes = current.to_bytes_be();
                if key_bytes.len() > 32 {
                    break;
                }

                let mut padded_key = [0u8; 32];
                let offset = 32 - key_bytes.len();
                padded_key[offset..].copy_from_slice(&key_bytes);

                // Compute public key
                if let Ok(secret_key) = SecretKey::from_slice(&padded_key) {
                    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                    let pubkey_bytes = public_key.serialize();
                    let pubkey_hex = hex::encode(&pubkey_bytes);

                    // Check prefix match (minimum 5 characters)
                    let mut match_len = 0;
                    for (a, b) in target_pubkey_hex.chars().zip(pubkey_hex.chars()) {
                        if a == b {
                            match_len += 1;
                        } else {
                            break;
                        }
                    }

                    if match_len >= 5 {
                        let priv_key_hex = hex::encode(&padded_key);
                        println!("✅ FOUND! Match Length: {} chars", match_len);
                        println!("   Private Key: {}", priv_key_hex);
                        println!("   Public Key:  {}", pubkey_hex);
                        println!("   Target:      {}", target_pubkey_hex);
                        println!("   Matching:    {}\n", &pubkey_hex[..match_len]);

                        found_count.fetch_add(1, Ordering::Relaxed);
                    }
                }

                let checked = checked_count.fetch_add(1, Ordering::Relaxed);

                // Print progress every chunk_size iterations
                if checked % chunk_size == 0 && checked > 0 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let rate = checked as f64 / elapsed;
                    println!(
                        "⏱️  Progress: {} keys checked | Speed: {:.0} keys/sec | Time: {:.2}s",
                        checked, rate, elapsed
                    );
                }

                current += 1u32;
            }
        });

    let elapsed = start.elapsed();
    let total_checked = checked_count.load(Ordering::Relaxed);
    let total_found = found_count.load(Ordering::Relaxed);
    let rate = total_checked as f64 / elapsed.as_secs_f64();

    println!("\n========================================");
    println!("🏁 Search Complete!");
    println!("========================================");
    println!("Total Keys Checked: {}", total_checked);
    println!("Total Matches Found: {}", total_found);
    println!("Speed: {:.0} keys/second", rate);
    println!("Execution Time: {:.2}s", elapsed.as_secs_f64());
    println!("========================================");
}
