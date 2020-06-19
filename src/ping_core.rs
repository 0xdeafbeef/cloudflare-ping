extern crate pnet;
use crate::ping_core::pnet::packet::FromPacket;
use crossbeam_channel::{unbounded, Receiver, Sender};
use ctrlc::set_handler;
use log::{debug, error, trace, warn};
use pnet::packet::icmp::{echo_reply::EchoReplyPacket, echo_request::MutableEchoRequestPacket};
use pnet::packet::icmp::{Icmp, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::MutablePacket;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer3};
use pnet::util;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Debug;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::process::exit;
use std::thread::sleep;
use std::time::{Duration, Instant};
use timeago::{Formatter, Language, TimeUnit};
use trust_dns_resolver::Resolver;

#[derive(Debug, PartialEq)]
pub struct Pinger {
    pub host: IpAddr,
    pub ttl: u8,
    pub timeout: Duration,
    pub requested_address: String,
}
static IPV4_HEADER_LEN: usize = 21;
static ICMP_HEADER_LEN: usize = 8;
static ICMP_PAYLOAD_LEN: usize = 32;

///creating new icmp echo_request_packet
/// passing buffer_ip and buffer_icmp
/// because packet consumes them
fn create_icmp_packet<'a>(
    buffer_ip: &'a mut [u8],
    buffer_icmp: &'a mut [u8],
    dest: Ipv4Addr,
    ttl: u8,
    sequence_number: u16,
) -> MutableIpv4Packet<'a> {
    let mut ipv4_packet = MutableIpv4Packet::new(buffer_ip).expect("Error creating ipv4 packet");
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);

    let mut icmp_packet =
        MutableEchoRequestPacket::new(buffer_icmp).expect("Error creating icmp packet");
    icmp_packet.set_sequence_number(sequence_number);
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = util::checksum(&icmp_packet.packet_mut(), 1);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(icmp_packet.packet_mut());
    ipv4_packet
}
/// creating new type just to format time as I want
struct FormatLang {}
impl Language for FormatLang {
    fn too_low(&self) -> &'static str {
        ""
    }

    fn too_high(&self) -> &'static str {
        unimplemented!()
    }

    fn ago(&self) -> &'static str {
        ""
    }

    fn get_word(&self, tu: TimeUnit, _x: u64) -> &'static str {
        match tu {
            TimeUnit::Nanoseconds => "ns",
            TimeUnit::Microseconds => "µs",
            TimeUnit::Milliseconds => "ms",
            TimeUnit::Seconds => "s",
            TimeUnit::Minutes => "M",
            TimeUnit::Hours => "H",
            TimeUnit::Days => "D",
            TimeUnit::Weeks => "W",
            _ => {
                "The world is changed. I feel it in the water. I feel it in the earth.\n\
            I smell it in the air (Elvish translation). Much that once was is lost;\n\
             for none now live who remember it."
            }
        }
    }
}

fn print_packet_recieved(
    total_packets: usize,
    sucess_packets: usize,
    formatter: &Formatter<FormatLang>,
    finish_time: Duration,
) {
    println!(
        "{} packets transmited, {} packets recieved, {:.2}% packet loss, time {}",
        total_packets,
        sucess_packets,
        (1.0 - (sucess_packets as f64 / total_packets as f64)) * 100.0,
        formatter.convert(finish_time)
    );
}

fn print_final_stats(address: String, stats: Receiver<Option<Duration>>, start_time: Instant) {
    let finish_time = Instant::now() - start_time;
    let stdout = io::stdout();
    let _handle = stdout.lock();
    //to stop the main thread of sending packets
    // when handle is active
    let stats: Vec<Option<Duration>> = stats.try_iter().collect();
    let total_packets = stats.len();
    let mut stats: Vec<Duration> = stats.into_iter().filter_map(|x| x).collect();
    let sucess_packets = stats.len();
    let lang = FormatLang {};
    let mut formatter = Formatter::with_language(lang);
    formatter
        .ago("")
        .num_items(1)
        .min_unit(timeago::TimeUnit::Nanoseconds);
    println!("--- {} ping statistics ---", address);
    if total_packets != 0 && !stats.is_empty() {
        let avg = stats.iter().cloned().sum::<Duration>() / stats.len() as u32;
        let max = stats.iter().cloned().max().unwrap();
        let min = stats.iter().cloned().min().unwrap();
        stats.sort();
        let median = stats[stats.len() / 2];
        let mut counts = HashMap::new();
        let mode = stats
            .iter()
            .copied()
            .max_by_key(|&n| {
                let count = counts.entry(n).or_insert(0);
                *count += 1;
                *count
            })
            .unwrap();
        print_packet_recieved(total_packets, sucess_packets, &formatter, finish_time);
        println!(
            "rtt min/max/median/mode/avg = {}/{}/{}/{}/{}",
            formatter.convert(min),
            formatter.convert(max),
            formatter.convert(median),
            formatter.convert(mode),
            formatter.convert(avg)
        );
    } else {
        print_packet_recieved(total_packets, sucess_packets, &formatter, finish_time);
    }
    exit(0);
}

fn resolve_potential_address(address: &str, ipv6_prefered: bool) -> Option<IpAddr> {
    let resolver = match Resolver::from_system_conf() {
        Ok(a) => {
            debug!("Resolver is set");
            a
        }
        Err(e) => {
            error!("Failed setting up resolver : {}", e);
            exit(1)
        }
    };
    let resloved = match resolver.lookup_ip(address) {
        Ok(a) => a,
        Err(e) => {
            error!("Resolve error : {}", e);
            return None;
        }
    };
    if ipv6_prefered {
        match resloved.iter().find(|a| a.is_ipv6()) {
            Some(a) => Some(a),
            None => resloved.iter().find(|a| a.is_ipv4()),
        }
    } else {
        resloved.iter().find(|a| a.is_ipv4())
    }
}
enum PrintStatsValues {
    PrintTimeExceedError,
    DoNotPrintTimeExceededError,
}
impl Pinger {
    /// ```
    /// use internship_application_systems::ping_core::Pinger;
    /// use std::time::Duration;
    /// use std::net::{Ipv4Addr, IpAddr};
    /// assert_eq!(Pinger::new("localhost", 64, Duration::from_secs(1)),
    /// Pinger{
    ///     host:IpAddr::from(Ipv4Addr::new(127,0,0,1)),
    ///     requested_address: "localhost".to_string(),
    ///     ttl: 64,
    ///     timeout : Duration::from_secs(1)
    /// });
    /// ```
    /// cretaes new instanse of pinger object
    /// all checks should be done on caller side
    pub fn new(address: &str, ttl: u8, timeout: Duration) -> Self {
        let addr: IpAddr = match address.parse::<IpAddr>() {
            Ok(a) => {
                debug!("Successfully parsed address. Started pinging {}", address);
                a
            }
            Err(e) => {
                debug!("Failed parsing as ip address: {}", e);
                match resolve_potential_address(address, false) {
                    Some(a) => {
                        debug!("Used {} for ping", a);
                        a
                    }
                    None => {
                        error!("No ips found");
                        exit(1);
                    }
                }
            }
        };
        Pinger {
            host: addr,
            ttl,
            timeout,
            requested_address: address.to_string(),
        }
    }
    fn parse_icmp_echo_replay_packet(payload: &[u8]) -> (u16, u8) {
        // offset is needed because of packet starts from ip.id field
        let icmp_payload = &payload[33 - 17..];
        let replay = EchoReplyPacket::new(icmp_payload)
            .expect("Error creating EchoReplyPacket from generic Icmp packet");
        let seq = replay.get_sequence_number();
        let ttl: u8 = payload[22 - 18]; //I am able to do this just because of error in lib design (:
        (seq, ttl)
    }
    ///checks, that ping response has arrived
    /// deconstructs packet and returns
    /// was ping ssuccessful or not
    fn print_stats(
        &self,
        pack: IcmpPacket,
        addr: IpAddr,
        ping_time: &mut HashMap<u16, Instant>,
        seq_n: u16,
    ) -> Result<Duration, PrintStatsValues> {
        let generic_icmp: Icmp = pack.from_packet();
        let size = generic_icmp.payload.len() + 18;
        // 18 is headers size minus strange offset.
        if addr == self.host {
            let (seq, ttl) = Pinger::parse_icmp_echo_replay_packet(&generic_icmp.payload);
            let time = match ping_time.get(&seq) {
                Some(a) => Instant::now() - *a,
                None => {
                    return Err(PrintStatsValues::PrintTimeExceedError);
                }
            };
            if time > self.timeout || seq_n != seq {
                return Err(PrintStatsValues::PrintTimeExceedError);
            }
            ping_time.remove(&seq);
            let lang = FormatLang {};
            let mut formatter = Formatter::with_language(lang);
            formatter
                .ago("")
                .num_items(2)
                .min_unit(timeago::TimeUnit::Nanoseconds);
            println!(
                "{} bytes from {}: icmp_seq={} ttl={} time={}",
                size,
                &self.host,
                seq,
                ttl,
                formatter.convert(time)
            );
            return Ok(time);
        //16 is number of icmp_type with strange shift
        //11 is icmp
        } else if generic_icmp.payload[16] == 11 {
            //thanks lipbnet again
            // 19 is strange  header offset
            // calcualted using wirshark
            // 69 to 71 is position of seq field in icmp packet of my configuration
            let seq_bytes: [u8; 2] = generic_icmp.payload[69 - 19..71 - 19]
                .try_into()
                .expect("slice with incorrect length");
            let seq = u16::from_be_bytes(seq_bytes);
            println!("From {} icmp_seq={} Time to live exceeded", addr, seq);
            return Err(PrintStatsValues::DoNotPrintTimeExceededError);
        }
        Err(PrintStatsValues::PrintTimeExceedError)
    }

    #[allow(clippy::match_wild_err_arm)]
    fn ping_ipv4(&mut self) {
        let (mut tx, mut rx) = transport_channel(2 << 15, Layer3(IpNextHeaderProtocols::Icmp))
            .map_err(|e| e.to_string())
            .expect("Failed creating transport channel. If you are seeing this try to `sudo setcap cap_net_raw+ep /path/to/exec`.\
             Or run program with sudo. Doesn't work on Os X. :(");
        let mut rx = icmp_packet_iter(&mut rx);
        let mut ping_time = HashMap::new();
        let mut seq_n = 0;
        let addr = match self.host {
            IpAddr::V4(a) => a,
            _ => unreachable!(),
        };
        println!(
            "PING {}({}) 32(54) bytes of data.",
            self.host, self.requested_address
        );
        let (ctrlc_tx, ctrlc_rx): (Sender<Option<Duration>>, Receiver<Option<Duration>>) =
            unbounded();
        let address_for_handler = self.requested_address.clone();
        let ping_start_time = Instant::now();
        set_handler(move || {
            print_final_stats(
                address_for_handler.clone(),
                ctrlc_rx.clone(),
                ping_start_time,
            )
        })
        .expect("Setting handler failed");
        loop {
            let mut buffer_ip = [0u8; 40];
            let mut buffer_icmp = [0u8; 40];
            let packet =
                create_icmp_packet(&mut buffer_ip, &mut buffer_icmp, addr, self.ttl, seq_n);
            //A separate scary story is aassociated with this part.
            // If you will compile release version without `RUSTFLAGS="-C target-cpu=native"`
            // it will segfault. Thanks, pnet.
            // I figured out the problem with inadequate work with unsafe code in pnet,
            // but I can't find, where it's happening now
            //In consequence with hacks
            // in .cargo/profile are created.
            // Normally works in debug mode, by the way.
            match tx.send_to(packet, IpAddr::V4(addr)) {
                Ok(_) => trace!("Sent icmp packet to {} with icmp_seq {}", addr, seq_n),
                Err(e) => warn!(
                    "Failed sending packet to {}  with icmp_seq {} : {}",
                    addr, seq_n, e
                ),
            }
            let mut ret = Err(PrintStatsValues::PrintTimeExceedError);
            let start_time = Instant::now();
            ping_time.insert(seq_n, start_time);
            // polling the icmp socket
            for _ in 0..7 {
                if let Ok(a) = rx.next_with_timeout(self.timeout / 10) {
                    if let Some((pack, addr)) = a {
                        ret = self.print_stats(pack, addr, &mut ping_time, seq_n);
                    }
                };
                if ret.is_ok() {
                    break;
                }
            }
            let now = Instant::now();
            // caluclates, how long should thread sleep
            // for case, when thread was polling for ping all the time
            if now - start_time < self.timeout {
                let sleep_time = self.timeout - (Instant::now() - start_time);
                sleep(sleep_time);
            }
            ping_time.remove(&seq_n);
            seq_n += 1;
            // If print_stats function prints nothing
            // then packet is not a `TimeExceededPacket`
            // so our packet hasn't arrived yet
            if let Err(e) = ret {
                if let PrintStatsValues::PrintTimeExceedError = e {
                    println!("Timeout for packet with seq_n={} exceeded", seq_n);
                }
                if let Err(e) = ctrlc_tx.send(None) {
                    warn!("Erorr while sending failed ping stat: {}", e);
                }
            } else if let Err(e) = ctrlc_tx.send(match ret {
                Ok(x) => Some(x),
                Err(_) => unimplemented!(),
            }) {
                error!("Error while sending ping stat : {}", e);
            }
        }
    }
    pub fn run(&mut self) {
        if let IpAddr::V4(_) = self.host {
            self.ping_ipv4()
        };
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_ok() {
        assert_eq!(
            resolve_potential_address("localhost", false),
            Some(IpAddr::from(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }
    
    #[test]
    fn test_resolver_fail() {
        assert_eq!(
            resolve_potential_address("blafefefoepw.com.suchdomain.doesnt.exist", false),
            None
        )
    }
    
    #[test]
    fn test_packet_parsing() {
        let packet_data = vec![
            4, 203, 0, 0, 49, 1, 162, 143, 1, 1, 1, 1, 192, 168, 31, 161, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (seq, ttl) = Pinger::parse_icmp_echo_replay_packet(&packet_data);
        assert_eq!((seq, ttl), (0, 49));
    }
}
