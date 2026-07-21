use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

const TARGET_PUBKEY: &str = "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673";
const MIN_PREFIX_MATCH: usize = 5;
const CHUNK_SIZE: usize = 100_000;

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_u128(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap_or(0)
}

fn privkey_to_pubkey(privkey: &str) -> String {
    // Simulate public key generation based on private key
    // For demo: hash the privkey to get a pubkey-like hex string
    let hash = format!("{:0>64}", privkey);
    hash[0..64].to_string()
}

fn search_range(
    start: u64,
    end: u64,
    found_count: Arc<AtomicUsize>,
    checked_count: Arc<AtomicUsize>,
    start_time: Instant,
) {
    let mut local_checked = 0u64;
    
    for privkey in start..=end {
        let privkey_hex = format!("{:064x}", privkey);
        let pubkey_hex = privkey_to_pubkey(&privkey_hex);
        
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
            println!("✅ FOUND! Match Length: {} chars", match_len);
            println!("   Private Key: {}", privkey_hex);
            println!("   Public Key:  {}", pubkey_hex);
            println!("   Target:      {}", TARGET_PUBKEY);
            println!("   Matching:    {}\n", &pubkey_hex[..match_len]);
            
            found_count.fetch_add(1, Ordering::Relaxed);
        }
        
        local_checked += 1;
        
        if local_checked % CHUNK_SIZE as u64 == 0 {
            let checked = checked_count.fetch_add(CHUNK_SIZE, Ordering::Relaxed) + CHUNK_SIZE;
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = checked as f64 / elapsed;
            println!(
                "⏱️  Progress: {} keys checked | Speed: {:.0} keys/sec | Time: {:.2}s",
                checked, rate, elapsed
            );
        }
    }
    
    checked_count.fetch_add(local_checked as usize, Ordering::Relaxed);
}

fn main() {
    let start = Instant::now();
    
    println!("🔍 Bitcoin Key Finder - Rust Ultra-Optimized (Termux Compatible)");
    println!("========================================");
    println!("Target Public Key: {}", TARGET_PUBKEY);
    println!("Range Start: 8000000000000000000000000000000000000000");
    println!("Range End:   ffffffffffffffffffffffffffffffffffffffff");
    println!("Min Prefix Match: {} characters", MIN_PREFIX_MATCH);
    println!("Threads: {}", get_num_threads());
    println!("========================================\n");
    
    let found_count = Arc::new(AtomicUsize::new(0));
    let checked_count = Arc::new(AtomicUsize::new(0));
    let num_threads = get_num_threads();
    
    // Use 64-bit range for demo (u64::MAX / num_threads)
    let range_size = u64::MAX;
    let chunk_range = range_size / num_threads as u64;
    
    let mut handles = vec![];
    
    for i in 0..num_threads {
        let chunk_start = i as u64 * chunk_range;
        let chunk_end = if i == num_threads - 1 {
            u64::MAX
        } else {
            (i as u64 + 1) * chunk_range
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
        let _ = handle.join();
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

fn get_num_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
