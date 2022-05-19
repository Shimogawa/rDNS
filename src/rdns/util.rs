use byteorder::{BigEndian, ReadBytesExt};
use rand::distributions::uniform::SampleUniform;
use rand::Rng;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

pub type Result<T> = core::result::Result<T, Box<dyn Error>>;

pub trait ReadExt: Read {
    #[inline]
    fn read_string_exact(&mut self, len: usize) -> Result<String> {
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        let s = String::from_utf8(buf)?;
        Ok(s)
    }

    #[inline]
    fn read_ipv4(&mut self) -> Result<Ipv4Addr> {
        Ok(Ipv4Addr::from(self.read_u32::<BigEndian>()?))
    }

    #[inline]
    fn read_ipv6(&mut self) -> Result<Ipv6Addr> {
        Ok(Ipv6Addr::from(self.read_u128::<BigEndian>()?))
    }

    #[inline]
    fn read_raw(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl<R: Read + ?Sized> ReadExt for R {}

pub trait WriteExt: Write {
    #[inline]
    fn write_string(&mut self, str: String) -> Result<()> {
        self.write(str.as_bytes())?;
        Ok(())
    }
}

impl<W: Write + ?Sized> WriteExt for W {}

pub trait RangeRandExtS<T> {
    fn rand(self) -> T;
}

pub trait RangeRandExtRS<T> {
    fn rand(&self) -> T;
}

impl<T: SampleUniform + PartialOrd> RangeRandExtS<T> for Range<T> {
    fn rand(self) -> T {
        let mut rng = rand::thread_rng();
        rng.gen_range(self)
    }
}

impl<T: Clone> RangeRandExtRS<T> for Vec<T> {
    fn rand(&self) -> T {
        let mut rng = rand::thread_rng();
        self[rng.gen_range(0..self.len())].clone()
    }
}

pub enum Either<L, R> {
    Left(L),
    Right(R),
}
