use crate::rdns::records::{
    DNSClass, DNSPacket, DNSQuestion, DNSRcode, DNSRdata, DNSType, ToDomainName, ToReadableName,
};
use crate::rdns::util::Either::{Left, Right};
use crate::rdns::util::{Either, RangeRandExtRS, RangeRandExtS, Result};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

const ROOT_SERVERS: [&str; 13] = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
];

fn get_a_root_addr() -> Result<IpAddr> {
    let a: IpAddr = ROOT_SERVERS[(0..ROOT_SERVERS.len()).rand()].parse()?;
    Ok(a)
}

pub struct RdnsData {
    src_addr: SocketAddr,
    packet_stack: Vec<DNSPacket>,
}

pub struct Rdns {
    socket: UdpSocket,
    id_map: HashMap<u16, RdnsData>,
}

impl Rdns {
    fn recv(&mut self, buf: &mut [u8]) -> (usize, SocketAddr) {
        self.socket.recv_from(buf).expect("no data received")
    }

    fn send_to(&self, addr: &SocketAddr, pkt: &DNSPacket) -> Result<()> {
        self.socket.send_to(&pkt.assemble()?, addr)?;
        Ok(())
    }

    pub fn start(&mut self) -> Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let (num_read, from_addr) = self.recv(&mut buf);
            let cbuf = &buf[..num_read];
            let mut received = match DNSPacket::from_raw(cbuf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            let id = received.id();
            if self.id_map.contains_key(&id) {
                let original = self.id_map.get(&id).unwrap();
                if original.src_addr == from_addr {
                    self.error(&mut received, DNSRcode::Refused, &from_addr)?;
                }
                if received.answers.len() != 0 {
                    if original.packet_stack.len() > 1 {
                        let addr = match received.answers[0].rdata.as_ref() {
                            DNSRdata::A(ip) => ip,
                            _ => {
                                // error: must be an A record
                                self.id_map.remove(&id).unwrap();
                                continue;
                            }
                        }
                        .clone();
                        self.id_map.get_mut(&id).unwrap().packet_stack.pop();
                        let original = self.id_map.get(&id).unwrap();
                        self.new_query(
                            &original.packet_stack.last().unwrap(),
                            &SocketAddr::new(addr.into(), 53),
                        )?;
                        continue;
                    }
                    let original = self.id_map.remove(&id).unwrap();
                    self.send_to(&original.src_addr, &received)?;
                    continue;
                }
                match self.check_for_ns_addr(&received) {
                    Right(names) => {
                        let n = &names[(0..names.len()).rand()];
                        self.query_for(id, n)?
                    }
                    Left(ip) => self.new_query(
                        &original.packet_stack.last().unwrap(),
                        &SocketAddr::new(ip.into(), 53),
                    )?,
                }
                continue;
            }
            // new query
            if !received.header.is_query() {
                continue;
            }
            if received.answers.len() != 0 {
                continue;
            }
            self.id_map.insert(
                id,
                RdnsData {
                    src_addr: from_addr,
                    packet_stack: vec![received],
                },
            );
            self.new_query(
                &self.id_map.get(&id).unwrap().packet_stack.last().unwrap(),
                &SocketAddr::new(get_a_root_addr()?, 53),
            )?;
        }
    }

    pub fn new(host: &str, port: u16) -> Result<Rdns> {
        let addr = SocketAddr::new(host.parse()?, port);
        let datamap = HashMap::new();
        let r = Rdns {
            socket: UdpSocket::bind(addr)?,
            id_map: datamap,
        };
        Ok(r)
    }

    fn query_for(&mut self, id: u16, domain_name: &String) -> Result<()> {
        if !self.id_map.contains_key(&id) {
            panic!("no");
        }
        let mut pkt = DNSPacket::new(id, true);
        pkt.questions.push(DNSQuestion {
            qname: domain_name.to_domain_name(),
            qclass: DNSClass::IN as u16,
            qtype: DNSType::A as u16,
        });
        self.new_query(&pkt, &SocketAddr::new(get_a_root_addr()?, 53))?;
        let data = self.id_map.get_mut(&id).unwrap();
        data.packet_stack.push(pkt);
        Ok(())
    }

    fn new_query(&self, pkt: &DNSPacket, to_addr: &SocketAddr) -> Result<()> {
        self.socket.send_to(&pkt.assemble()?, to_addr)?;
        Ok(())
    }

    fn check_for_ns_addr(&self, pkt: &DNSPacket) -> Either<Ipv4Addr, Vec<String>> {
        let mut nameservs = HashSet::new();
        for x in &pkt.authorities {
            if x.r#type == DNSType::NS as u16 {
                if let DNSRdata::Ns(dn) = x.rdata.as_ref() {
                    nameservs.insert(dn.to_domain_name());
                }
            }
        }
        let mut v = Vec::new();
        for x in &pkt.additionals {
            if let DNSRdata::A(ip) = x.rdata.as_ref() {
                if nameservs.contains(x.name.to_domain_name().as_str()) {
                    v.push(ip);
                }
            }
        }
        if v.is_empty() {
            return Right(nameservs.into_iter().collect());
        }
        Left(*v.rand())
    }

    fn error(&self, pkt: &mut DNSPacket, rcode: DNSRcode, addr: &SocketAddr) -> Result<()> {
        pkt.header.set_rcode(rcode);
        self.send_to(&addr, pkt)?;
        Ok(())
    }
}
