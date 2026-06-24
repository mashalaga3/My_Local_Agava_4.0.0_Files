//! Control Test - Normal Filter (للمقارنة)
use std::{net::{SocketAddr, UdpSocket}, sync::{Arc, atomic::{AtomicU64, AtomicBool, Ordering}}, thread, time::{Duration, Instant}};
use bincode;
use bitvec::prelude::*;
use serde::{Serialize, Deserialize};
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::pubkey::Pubkey;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Bloom { keys: Vec<u64>, bits: BitVec<u8>, num_bits_set: u64 }
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CrdsFilter { filter: Bloom, mask: u64, mask_bits: u32 }
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ContactInfo { pubkey: Pubkey, wallclock: u64, shred_version: u16 }
#[derive(Serialize, Deserialize, Debug, Clone)]
enum CrdsData { ContactInfo(ContactInfo) }
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CrdsValue { data: CrdsData, #[serde(with = "serde_bytes")] signature: [u8; 64] }
#[derive(Serialize, Deserialize, Debug, Clone)]
enum Protocol { PullRequest(CrdsFilter, CrdsValue) }

fn sig_to_bytes(kp: &Keypair, msg: &[u8]) -> [u8; 64] {
    let s = kp.sign_message(msg); let mut o=[0u8;64]; o.copy_from_slice(s.as_ref()); o
}

fn build_normal_filter() -> CrdsFilter {
    let keys: Vec<u64> = (0..3).map(|i| i as u64 + 1).collect();
    let mut bits = bitvec![u8, Lsb0; 0; 7865];
    for i in 0..(7865 * 5 / 100) { bits.set(i, true); }
    CrdsFilter { filter: Bloom { keys, bits, num_bits_set: 393 }, mask: 0, mask_bits: 6 }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let addr: SocketAddr = args[1].parse().unwrap();
    let shred_ver: u16 = args[2].parse().unwrap();
    
    println!("[Control Test] Normal Filter - 30 seconds");
    
    let counter = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    
    for i in 0..8 {
        let c = Arc::clone(&counter);
        let s = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            let kp = Keypair::new();
            let filter = build_normal_filter();
            let contact = ContactInfo { pubkey: kp.pubkey(), wallclock: 1000+i as u64, shred_version: shred_ver };
            let data = CrdsData::ContactInfo(contact);
            let data_bytes = bincode::serialize(&data).unwrap();
            let val = CrdsValue { data, signature: sig_to_bytes(&kp, &data_bytes) };
            let pkt = bincode::serialize(&Protocol::PullRequest(filter, val)).unwrap();
            while !s.load(Ordering::Relaxed) {
                for _ in 0..100 {
                    if socket.send_to(&pkt, addr).is_ok() { c.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }));
    }
    
    let start = Instant::now();
    loop {
        let e = start.elapsed().as_secs();
        if e >= 30 { break; }
        thread::sleep(Duration::from_secs(5));
        println!("[{:>2}s] Packets sent: {}", e, counter.load(Ordering::Relaxed));
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles { h.join().unwrap(); }
    println!("[Control Test] Complete: {} packets in 30s", counter.load(Ordering::Relaxed));
}
