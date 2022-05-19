use super::util::Result;
use byteorder::WriteBytesExt;
use std::io::Write;

pub type DomainName = Vec<String>;

pub trait ToDomainName {
    fn to_domain_name(&self) -> DomainName;
}

impl ToDomainName for String {
    fn to_domain_name(&self) -> DomainName {
        self.split(".").map(|x| x.to_string()).collect()
    }
}

pub trait ToReadableName {
    fn to_domain_name(&self) -> String;
}

impl ToReadableName for DomainName {
    fn to_domain_name(&self) -> String {
        if self.is_empty() {
            return String::from(".");
        }
        let mut res = String::new();
        for x in self {
            res.push_str(x);
            res.push('.');
        }
        res.remove(res.len() - 1);
        res
    }
}

pub trait DomainNameToBytes {
    fn to_bytes(&self) -> Result<Vec<u8>>;
}

impl DomainNameToBytes for DomainName {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut res = Vec::new();
        for d in self {
            res.write_u8(d.len() as u8)?;
            res.write(d.as_bytes())?;
        }
        res.write_u8(0)?;
        Ok(res)
    }
}
