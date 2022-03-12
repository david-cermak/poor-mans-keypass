use std::io::{self, stdin, stdout, Write};
use std::net::TcpStream;
use std::sync::Arc;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::Certificate;
use mbedtls::Result as TlsResult;
use std::time::Duration;
use serialport::SerialPort;

pub const PEM_CERT: &'static str = concat!(include_str!("../../keys/client.crt"),"\0");
pub fn entropy_new() -> mbedtls::rng::OsEntropy {
    mbedtls::rng::OsEntropy::new()
}


fn result_main(port: Box<dyn SerialPort>) -> TlsResult<()> {
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(PEM_CERT.as_bytes())?);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_ca_list(cert, None);
    let mut ctx = Context::new(Arc::new(config));

    // TODO: wrap port to Sync + Send impl trait
    ctx.establish(port, None)?;

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();
    ctx.write_all(line.as_bytes()).unwrap();
    io::copy(&mut ctx, &mut stdout()).unwrap();
    Ok(())
}

fn main() {
    let mut args = std::env::args();
    args.next();
    let port = serialport::new("/dev/ttyUSB0", 115_200)
        .timeout(Duration::from_millis(10))
        .open().expect("Failed to open port");
    result_main(
        port
    )
        .unwrap();
}
