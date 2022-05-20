use crate::rdns::domain_name::{DomainName, DomainNameToBytes, ToReadableName};
use crate::rdns::util::{ReadExt, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::fmt::Debug;
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

#[derive(Debug, Clone)]
pub struct DNSPacket {
    /// DNS packet header part
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSResourceRecord>,
    pub authorities: Vec<DNSResourceRecord>,
    pub additionals: Vec<DNSResourceRecord>,
}

#[derive(FromPrimitive, Debug, Copy, Clone)]
pub enum DNSRcode {
    Normal = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,

    Unknown = -1,
}

impl DNSRcode {
    pub fn from_num(n: u16) -> Self {
        FromPrimitive::from_u16(n).unwrap_or(Self::Unknown)
    }
}

/// DNS packet header part
#[derive(Debug, Clone)]
pub struct DNSHeader {
    /// id
    pub id: u16,
    /// A one bit field that specifies whether this message is a
    /// query (0), or a response (1).
    pub qr: u8,
    /// A four bit field that specifies kind of query in this
    /// message.
    pub opcode: u8,
    /// Authoritative Answer
    pub aa: u8,
    /// TrunCation
    pub tc: u8,
    /// Recursion Desired
    pub rd: u8,
    /// Recursion Available
    pub ra: u8,
    /// Reserved
    pub reserved: u8,
    /// Response code
    pub rcode: u8,
    /// number of entries in the question section
    pub qdcount: u16,
    /// number of resource records in the answer section
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, Clone)]
pub struct DNSQuestion {
    pub qname: DomainName,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DNSResourceRecord {
    pub name: DomainName,
    pub r#type: u16,
    pub class: u16,
    /// the time interval (in seconds) that the resource record
    /// may be cached before it should be discarded
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Rc<DNSRdata>,
}

#[derive(Debug)]
pub enum DNSRdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(DomainName),
    Mx(u16, DomainName),
    Ns(DomainName),
    Txt(String),
    Other(Vec<u8>),
}

impl DNSRdata {
    fn to_bytes(&self, writer: &mut Vec<u8>) -> Result<()> {
        let buf: Vec<u8> = match self {
            Self::A(ip) => Vec::from(ip.octets()),
            Self::Aaaa(ip) => Vec::from(ip.octets()),
            Self::Cname(dn) => dn.to_bytes()?,
            Self::Mx(pref, dn) => {
                let mut v = Vec::new();
                v.write_u16::<BigEndian>(*pref)?;
                v.append(&mut dn.to_bytes()?);
                v
            }
            Self::Ns(dn) => dn.to_bytes()?,
            Self::Txt(s) => Vec::from(s.as_bytes()),
            Self::Other(raw) => raw.to_vec(),
        };
        writer.write_u16::<BigEndian>(buf.len() as u16)?;
        writer.write(&buf)?;
        Ok(())
    }

    fn get_type(&self) -> Option<DNSType> {
        let t = match self {
            Self::A(_) => DNSType::A,
            Self::Aaaa(_) => DNSType::AAAA,
            Self::Cname(_) => DNSType::CNAME,
            Self::Mx(_, _) => DNSType::MX,
            Self::Ns(_) => DNSType::NS,
            Self::Txt(_) => DNSType::TXT,
            Self::Other(_) => DNSType::NotImplemented,
        };
        if t != DNSType::NotImplemented {
            Some(t)
        } else {
            None
        }
    }
}

pub trait ReadDomainName {
    fn read_domain_name(&mut self) -> Result<DomainName>;
}

impl ReadDomainName for Cursor<&[u8]> {
    fn read_domain_name(&mut self) -> Result<DomainName> {
        let mut res: DomainName = Vec::new();
        loop {
            let cnt = self.read_u8()?;
            if cnt == 0 {
                break;
            }
            // if is 11xxxxxx
            if cnt >> 6 == 0x3 {
                self.set_position(self.position() - 1);
                let ptr = self.read_u16::<BigEndian>()? & 0x3FFFu16;
                let cur_pos = self.position();
                self.set_position(ptr as u64);
                let dn = self.read_domain_name()?;
                self.set_position(cur_pos);
                res.extend(dn);
                return Ok(res);
            }
            let d = self.read_string_exact(cnt as usize)?;
            res.push(d);
        }
        Ok(res)
    }
}

#[derive(FromPrimitive, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum DNSType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    AFSDB = 18,
    AAAA = 28,
    OPT = 41,
    APL = 42,
    IPSECKEY = 45,
    RRSIG = 46,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ALL = 255,

    NotImplemented = -1,
}

impl DNSType {
    pub fn from_num(n: u16) -> Self {
        FromPrimitive::from_u16(n).unwrap_or(Self::NotImplemented)
    }
}

impl From<u16> for DNSType {
    fn from(n: u16) -> Self {
        Self::from_num(n)
    }
}

#[derive(FromPrimitive, Debug, Copy, Clone)]
pub enum DNSClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255,

    NotImplemented = -1,
}

impl DNSClass {
    pub fn from_num(n: u16) -> Self {
        FromPrimitive::from_u16(n).unwrap_or(Self::NotImplemented)
    }
}

impl DNSPacket {
    pub fn id(&self) -> u16 {
        self.header.id
    }

    pub fn from_raw(buf: &[u8]) -> Result<DNSPacket> {
        let mut rdr = Cursor::new(buf);
        let header = DNSHeader::from_raw(&mut rdr)?;
        let questions = DNSQuestion::from_raw(&mut rdr, header.qdcount)?;
        let answers = DNSResourceRecord::from_raw_multi(&mut rdr, header.ancount)?;
        let authorities = DNSResourceRecord::from_raw_multi(&mut rdr, header.nscount)?;
        let additionals = DNSResourceRecord::from_raw_multi(&mut rdr, header.arcount)?;
        Ok(DNSPacket {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn assemble(&self) -> Result<Vec<u8>> {
        let mut writer: Vec<u8> = Vec::new();
        self.header.to_bytes(
            &mut writer,
            self.questions.len() as u16,
            self.answers.len() as u16,
            self.authorities.len() as u16,
            self.additionals.len() as u16,
        )?;
        for q in &self.questions {
            q.to_bytes(&mut writer)?;
        }
        for rr in &self.answers {
            rr.to_bytes(&mut writer)?;
        }
        for rr in &self.authorities {
            rr.to_bytes(&mut writer)?;
        }
        for rr in &self.additionals {
            rr.to_bytes(&mut writer)?;
        }
        Ok(writer)
    }

    pub fn new(id: u16, is_query: bool) -> Self {
        Self {
            header: DNSHeader::new(id, is_query),
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }
}

impl DNSHeader {
    pub fn from_raw(rdr: &mut Cursor<&[u8]>) -> Result<Self> {
        let id = rdr.read_u16::<BigEndian>()?;
        let tmp1 = rdr.read_u8()?;
        let tmp2 = rdr.read_u8()?;
        let qdcount = rdr.read_u16::<BigEndian>()?;
        let ancount = rdr.read_u16::<BigEndian>()?;
        let nscount = rdr.read_u16::<BigEndian>()?;
        let arcount = rdr.read_u16::<BigEndian>()?;
        let qr = tmp1 >> 7 & 0x1;
        let opcode = tmp1 >> 3 & 0xF;
        let aa = tmp1 >> 2 & 0x1;
        let tc = tmp1 >> 1 & 0x1;
        let rd = tmp1 & 0x1;
        let ra = tmp2 >> 7 & 0x1;
        let reserved = tmp2 >> 4 & 0x7;
        let rcode = tmp2 & 0xF;
        Ok(Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            reserved,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    pub fn is_query(&self) -> bool {
        self.qr == 0
    }

    pub fn set_rcode(&mut self, rcode: DNSRcode) {
        self.rcode = rcode as u8;
    }

    pub fn to_bytes(
        &self,
        writer: &mut Vec<u8>,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) -> Result<()> {
        writer.write_u16::<BigEndian>(self.id)?;
        writer.write_u8((self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.rd))?;
        writer.write_u8((self.ra << 7) | (self.reserved << 4) | self.rcode)?;
        writer.write_u16::<BigEndian>(qdcount)?;
        writer.write_u16::<BigEndian>(ancount)?;
        writer.write_u16::<BigEndian>(nscount)?;
        writer.write_u16::<BigEndian>(arcount)?;
        Ok(())
    }

    pub fn new(id: u16, is_query: bool) -> Self {
        Self {
            id,
            qr: if is_query { 0 } else { 1 },
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            reserved: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}

impl DNSQuestion {
    pub fn from_raw(rdr: &mut Cursor<&[u8]>, count: u16) -> Result<Vec<DNSQuestion>> {
        let mut res: Vec<DNSQuestion> = Vec::new();
        for _ in 0..count {
            let qname = rdr.read_domain_name()?;
            let qtype = rdr.read_u16::<BigEndian>()?;
            let qclass = rdr.read_u16::<BigEndian>()?;
            res.push(DNSQuestion {
                qname,
                qtype,
                qclass,
            });
        }
        Ok(res)
    }

    pub fn domain_name(&self) -> String {
        self.qname.to_domain_name()
    }

    pub fn to_bytes(&self, writer: &mut Vec<u8>) -> Result<()> {
        writer.write(&self.qname.to_bytes()?)?;
        writer.write_u16::<BigEndian>(self.qtype)?;
        writer.write_u16::<BigEndian>(self.qclass)?;
        Ok(())
    }

    pub fn new(qname: DomainName, qtype: u16) -> Self {
        Self {
            qname,
            qtype,
            qclass: DNSClass::IN as u16,
        }
    }
}

impl DNSResourceRecord {
    pub fn rdata_from_raw(rdr: &mut Cursor<&[u8]>, rtype: u16) -> Result<(u16, Rc<DNSRdata>)> {
        let rdlength = rdr.read_u16::<BigEndian>()?;
        let rdata: Rc<DNSRdata> = Rc::new(match DNSType::from_num(rtype) {
            DNSType::A => DNSRdata::A(rdr.read_ipv4()?),
            DNSType::AAAA => DNSRdata::Aaaa(rdr.read_ipv6()?),
            DNSType::CNAME => DNSRdata::Cname(rdr.read_domain_name()?),
            DNSType::MX => DNSRdata::Mx(rdr.read_u16::<BigEndian>()?, rdr.read_domain_name()?),
            DNSType::NS => DNSRdata::Ns(rdr.read_domain_name()?),
            DNSType::TXT => DNSRdata::Txt(rdr.read_string_exact(rdlength as usize)?),
            _ => DNSRdata::Other(rdr.read_raw(rdlength as usize)?),
        });
        Ok((rdlength, rdata))
    }

    pub fn from_raw_multi(rdr: &mut Cursor<&[u8]>, count: u16) -> Result<Vec<Self>> {
        let mut res: Vec<Self> = Vec::new();
        for _ in 0..count {
            res.push(Self::from_raw(rdr)?);
        }
        Ok(res)
    }

    pub fn from_raw(rdr: &mut Cursor<&[u8]>) -> Result<Self> {
        let name = rdr.read_domain_name()?;
        let r#type = rdr.read_u16::<BigEndian>()?;
        let class = rdr.read_u16::<BigEndian>()?;
        let ttl = rdr.read_u32::<BigEndian>()?;
        let (rdlength, rdata) = Self::rdata_from_raw(rdr, r#type)?;
        Ok(Self {
            name,
            r#type,
            class,
            ttl,
            rdlength,
            rdata,
        })
    }

    pub fn to_bytes(&self, writer: &mut Vec<u8>) -> Result<()> {
        writer.write(&self.name.to_bytes()?)?;
        // use `rdata` type first, if is type "other",
        // use the `type` field
        writer.write_u16::<BigEndian>(
            self.rdata
                .get_type()
                .map(|x| x as u16)
                .unwrap_or(self.r#type),
        )?;
        writer.write_u16::<BigEndian>(self.class)?;
        writer.write_u32::<BigEndian>(self.ttl)?;
        self.rdata.to_bytes(writer)?;
        Ok(())
    }
}
