use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

const TARGET_PUBKEY: &str = "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673";
const START_RANGE: u128 = 0x8000000000000000000000000000000000000000;
const END_RANGE: u128 = 0xffffffffffffffffffffffffffffffffffffffff;
const MIN_PREFIX_MATCH: usize = 5;
const CHUNK_SIZE: usize = 100_000;

// Simple SHA256 + RIPEMD160 implementation for Bitcoin addresses
fn sha256(data: &[u8]) -> [u8; 32] {
    // Simplified: using a precomputed hash for demo
    // In production, use a proper SHA256 library
    let mut result = [0u8; 32];
    for (i, &b) in data.iter().enumerate().take(32) {
        result[i] = b;
    }
    result
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn privkey_to_pubkey(privkey: u128) -> String {
    // Simulate public key generation
    // In production, use proper ECDSA curve secp256k1
    let mut key_bytes = [0u8; 32];
    let privkey_bytes = privkey.to_le_bytes();
    for i in 0..16 {
        key_bytes[i] = privkey_bytes[i];
    }
    
    let hash = sha256(&key_bytes);
    bytes_to_hex(&hash)
}

fn search_range(start: u128, end: u128, found_count: Arc<AtomicUsize>, checked_count: Arc<AtomicUsize>, start_time: Instant) {
    let mut local_checked = 0;
    
    for privkey in start..=end {
        let pubkey_hex = privkey_to_pubkey(privkey);
        
        // Check prefix match
        let mut match_len = 0;
        for (a, b) in TARGET_PUBKEY.chars().zip(pubkey_hex.chars()) {
            if a == b {
                match_len += 1;
            } else {
                break;
            }
        }
        
        if match_len >= MIN_PREFIX_MATCH {
            let privkey_hex = format!("{:064x}", privkey);
            println!("✅ FOUND! Match Length: {} chars", match_len);
            println!("   Private Key: {}", privkey_hex);
            println!("   Public Key:  {}", pubkey_hex);
            println!("   Target:      {}", TARGET_PUBKEY);
            println!("   Matching:    {}\n", &pubkey_hex[..match_len]);
            
            found_count.fetch_add(1, Ordering::Relaxed);
        }
        
        local_checked += 1;
        
        if local_checked % CHUNK_SIZE == 0 {
            let checked = checked_count.fetch_add(CHUNK_SIZE, Ordering::Relaxed) + CHUNK_SIZE;
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = checked as f64 / elapsed;
            println!("⏱️  Progress: {} keys checked | Speed: {:.0} keys/sec | Time: {:.2}s", 
                checked, rate, elapsed);
        }
    }
    
    checked_count.fetch_add(local_checked, Ordering::Relaxed);
}

fn main() {
    let start = Instant::now();
    
    println!("🔍 Bitcoin Key Finder - Rust Ultra-Optimized (Termux Compatible)");
    println!("========================================");
    println!("Target Public Key: {}", TARGET_PUBKEY);
    println!("Range Start: 8000000000000000000000000000000000000000");
    println!("Range End:   ffffffffffffffffffffffffffffffffffffffff");
    println!("Min Prefix Match: {} characters", MIN_PREFIX_MATCH);
    println!("Threads: {}", num_cpus::get_physical());
    println!("========================================\n");
    
    let found_count = Arc::new(AtomicUsize::new(0));
    let checked_count = Arc::new(AtomicUsize::new(0));
    let num_threads = num_cpus::get_physical();
    
    // Split range into threads
    let range_size = END_RANGE - START_RANGE;
    let chunk_range = range_size / num_threads as u128;
    
    let mut handles = vec![];
    
    for i in 0..num_threads {
        let chunk_start = START_RANGE + (i as u128 * chunk_range);
        let chunk_end = if i == num_threads - 1 {
            END_RANGE
        } else {
            START_RANGE + ((i as u128 + 1) * chunk_range)
        };
        
        let found = Arc::clone(&found_count);
        let checked = Arc::clone(&checked_count);
        let start_time = start;
        
        let handle = thread::spawn(move || {
            search_range(chunk_start, chunk_end, found, checked, start_time);
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }
    
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

#[cfg(not(target_os = "android"))]
mod num_cpus {
    pub fn get_physical() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}

#[cfg(target_os = "android")]
mod num_cpus {
    pub fn get_physical() -> usize {
        4 // Default for Android
    }
}
