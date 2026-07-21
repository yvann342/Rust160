use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

fn main() {
    let start = Instant::now();
    
    println!("🔍 Bitcoin Key Finder - Rust");
    println!("========================================");
    println!("Target Public Key: 02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673");
    println!("Min Prefix Match: 5 characters");
    println!("========================================\n");
    
    let found = Arc::new(Mutex::new(0usize));
    let checked = Arc::new(Mutex::new(0usize));
    
    let num_threads = 4;
    let mut handles = vec![];
    
    // Simple search in a smaller range for demo
    let range_per_thread = 1_000_000u64;
    
    for thread_id in 0..num_threads {
        let found_clone = Arc::clone(&found);
        let checked_clone = Arc::clone(&checked);
        let start_time = start;
        
        let handle = thread::spawn(move || {
            let thread_start = thread_id as u64 * range_per_thread;
            let thread_end = thread_start + range_per_thread;
            
            for privkey in thread_start..thread_end {
                // Simple hash: convert to hex string
                let privkey_hex = format!("{:064x}", privkey);
                
                // Generate fake pubkey (just reverse first chars for demo)
                let pubkey_hex = format!("02{:062x}", privkey ^ 0xdeadbeef);
                
                // Check if starts with "02e0a8"
                if pubkey_hex.starts_with("02e0a8") {
                    println!("✅ FOUND!");
                    println!("   Private Key: {}", privkey_hex);
                    println!("   Public Key:  {}", pubkey_hex);
                    
                    let mut f = found_clone.lock().unwrap();
                    *f += 1;
                }
                
                let mut c = checked_clone.lock().unwrap();
                *c += 1;
                
                if *c % 100_000 == 0 {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let rate = *c as f64 / elapsed;
                    println!("⏱️  Thread {}: {} keys | {:.0} keys/sec", thread_id, *c, rate);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.join();
    }
    
    let elapsed = start.elapsed();
    let total_checked = *checked.lock().unwrap();
    let total_found = *found.lock().unwrap();
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
