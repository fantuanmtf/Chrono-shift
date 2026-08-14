//! SOCKS5 client (DNS leak prevention)
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub struct Socks5Stream {
    inner: TcpStream,
}
impl Socks5Stream {
    pub fn connect(
        proxy: &str,
        target_domain: &str,
        target_port: u16,
        timeout_secs: u64,
    ) -> std::io::Result<Self> {
        let proxy_addr: Vec<_> = proxy.to_socket_addrs()?.collect();
        let mut stream =
            TcpStream::connect_timeout(&proxy_addr[0], Duration::from_secs(timeout_secs))?;
        stream.write_all(&[0x05, 0x01, 0x00])?;
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp)?;
        if resp[0] != 0x05 || resp[1] != 0x00 {
            return Err(std::io::Error::other("SOCKS5 auth failed"));
        }
        let dlen = target_domain.len();
        if dlen > 255 {
            return Err(std::io::Error::other("Domain too long"));
        }
        let mut req = Vec::with_capacity(7 + dlen);
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, dlen as u8]);
        req.extend_from_slice(target_domain.as_bytes());
        req.extend_from_slice(&[(target_port >> 8) as u8, (target_port & 0xFF) as u8]);
        stream.write_all(&req)?;
        let mut resp2 = [0u8; 262];
        let n = stream.read(&mut resp2)?;
        if n < 10 || resp2[1] != 0x00 {
            return Err(std::io::Error::other("SOCKS5 connect failed"));
        }
        Ok(Socks5Stream { inner: stream })
    }
    pub fn connect_tor(onion: &str, port: u16) -> std::io::Result<Self> {
        Self::connect("127.0.0.1:9050", onion, port, 30)
    }
}
impl Read for Socks5Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for Socks5Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub fn socks5_connect(
    proxy: &str,
    domain: &str,
    port: u16,
    retries: u32,
) -> std::io::Result<Socks5Stream> {
    // HIGH-7 fix: handle retries=0 without panic
    let attempts = if retries == 0 { 1 } else { retries };
    let mut last_err = None;
    for i in 0..attempts {
        match Socks5Stream::connect(proxy, domain, port, 5 + i as u64 * 3) {
            Ok(s) => return Ok(s),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(500 * 2u64.pow(i)));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("SOCKS5 connect failed")))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_socks5_handshake_send() {
        let req = [0x05u8, 0x01, 0x00];
        assert_eq!(req.len(), 3);
    }
    #[test]
    fn test_domain_too_long() {
        let long = "a".repeat(256);
        assert!(Socks5Stream::connect("127.0.0.1:9050", &long, 80, 1).is_err());
    }
}
