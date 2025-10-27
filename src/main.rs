use anyhow::Error;
use anyhow::anyhow;
use anyhow::bail;
use byteorder::{LittleEndian, ReadBytesExt as _, WriteBytesExt as _};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::ToSocketAddrs as _;

const ADDR: &str = "clearsky.dev:29438";
const MAGIC: u32 = 0x4b325258;
const LOGIN_INFO_PATH: &str = "login_info.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PacketType {
    Help,
    Hello,
    Documentation,
    Register,
    Registered,
    Login,
    GetStatus,
    Status,
    GetMail,
    Mail,
    SendMail,
    Configure,
    Route,
    Translate,
    Translation,
    Result,
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use PacketType::*;

        let val = match value {
            0x00 => Help,
            0x01 => Hello,
            0x02 => Documentation,
            0x03 => Register,
            0x04 => Registered,
            0x05 => Login,
            0x07 => GetStatus,
            0x08 => Status,
            0x09 => GetMail,
            0x0a => Mail,
            0x0b => SendMail,
            0x12 => Configure,
            0x14 => Route,
            0x15 => Translate,
            0x16 => Translation,
            0x1f => Result,

            _ => bail!("Invalid packet type"),
        };

        Ok(val)
    }
}

impl From<PacketType> for u8 {
    fn from(value: PacketType) -> Self {
        use PacketType::*;

        match value {
            Help => 0x00,
            Hello => 0x01,
            Documentation => 0x02,
            Register => 0x03,
            Registered => 0x04,
            Login => 0x05,
            GetStatus => 0x07,
            Status => 0x08,
            GetMail => 0x09,
            Mail => 0x0a,
            SendMail => 0x0b,
            Configure => 0x12,
            Route => 0x14,
            Translate => 0x15,
            Translation => 0x16,
            Result => 0x1f,
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Incoming,
    Outgoing,
}

struct Packet {
    packet_type: PacketType,
    request_id: Option<u8>,
    payload: Vec<u8>,
}

impl Packet {
    fn dump_packet(&self, dir: Direction) {
        let prefix = match dir {
            Direction::Incoming => "<<",
            Direction::Outgoing => ">>",
        };
        println!(
            "{} type = {:?}, request_id = {:?}",
            prefix, self.packet_type, self.request_id
        );

        if !self.payload.is_empty() {
            hexdump::hexdump(&self.payload);
        }
    }
}

#[derive(Debug)]
struct RawHeader {
    lfl: u8,
    request_id_present: u8,
    packet_type: u8,
}

impl RawHeader {
    fn is_valid(&self) -> bool {
        (0..=3).contains(&self.lfl)
            && (0..=1).contains(&self.request_id_present)
            && (0..=0x1f).contains(&self.packet_type)
    }
}

impl From<u8> for RawHeader {
    fn from(value: u8) -> Self {
        let lfl = value >> 6;
        let request_id_present = value >> 5 & 1;
        let packet_type = value & 0b11111;

        let res = Self {
            lfl,
            request_id_present,
            packet_type,
        };

        assert!(res.is_valid());
        res
    }
}

impl From<RawHeader> for u8 {
    fn from(value: RawHeader) -> Self {
        assert!(value.is_valid());
        let mut b: u8 = 0;
        b |= value.lfl << 6;
        b |= value.request_id_present << 5;
        b |= value.packet_type;
        b
    }
}

fn read_packet(mut stream: impl Read) -> Result<Packet, Error> {
    let header = RawHeader::from(stream.read_u8()?);

    let request_id = if header.request_id_present != 0 {
        Some(stream.read_u8()?)
    } else {
        None
    };
    let magic = stream.read_u32::<LittleEndian>()?;

    if magic != MAGIC {
        bail!("invalid magic")
    }

    let packet_type = PacketType::try_from(header.packet_type)?;

    let payload_len = match header.lfl {
        0 => 0,
        1 => stream.read_u8()? as usize,
        2 => stream.read_u16::<LittleEndian>()? as usize,
        3 => stream.read_u32::<LittleEndian>()? as usize,
        _ => unreachable!(),
    };

    let mut payload = Vec::new();
    payload.resize_with(payload_len, Default::default);
    stream.read_exact(&mut payload)?;

    let pkt = Packet {
        packet_type,
        request_id,
        payload,
    };

    pkt.dump_packet(Direction::Incoming);

    Ok(pkt)
}

fn write_packet(mut stream: impl Write, pkt: &Packet) -> Result<(), Error> {
    pkt.dump_packet(Direction::Outgoing);
    let lfl = match pkt.payload.len() {
        0x0 => 0,
        0x1..=0xff => 1,
        0x100..=0xffff => 2,
        0x10000..=0xffffffff => 3,
        _ => {
            bail!("payload too large")
        }
    };

    let header = RawHeader {
        lfl,
        request_id_present: if pkt.request_id.is_some() { 1 } else { 0 },
        packet_type: u8::from(pkt.packet_type),
    };

    stream.write_all(&[u8::from(header)])?;

    if let Some(request_id) = pkt.request_id {
        stream.write_all(&[request_id])?;
    }

    stream.write_u32::<LittleEndian>(MAGIC)?;

    match lfl {
        0 => {}
        1 => {
            stream.write_u8(pkt.payload.len() as u8)?;
        }
        2 => {
            stream.write_u16::<LittleEndian>(pkt.payload.len() as u16)?;
        }
        3 => {
            stream.write_u32::<LittleEndian>(pkt.payload.len() as u32)?;
        }
        _ => {
            unreachable!()
        }
    }

    stream.write_all(&pkt.payload)?;

    Ok(())
}

fn do_request(req: &mut Packet, mut stream: impl Read + Write) -> Result<Packet, Error> {
    req.request_id = Some(rand::random::<u8>());

    write_packet(&mut stream, req)?;
    let resp = read_packet(&mut stream)?;

    if resp.request_id != req.request_id {
        bail!("mismatched request_id");
    }

    Ok(resp)
}

#[derive(Serialize, Deserialize, Debug)]
struct LoginInfo {
    username: String,
    password: String,
}

fn read_string(mut stream: impl Read) -> Result<String, Error> {
    let len = usize::from(stream.read_u8()?);
    let mut buf = vec![0; len];
    stream.read_exact(&mut buf)?;
    let s = String::from_utf8(buf)?;
    Ok(s)
}

fn write_string(mut stream: impl Write, value: &str) -> Result<(), Error> {
    let len = u8::try_from(value.len())?;
    stream.write_u8(len)?;
    stream.write_all(value.as_bytes())?;
    Ok(())
}

fn main() -> Result<(), Error> {
    let addr = ADDR
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("addr didn't resolve to any addresses"))?;

    let mut stream = TcpStream::connect(addr)?;

    let hello_pkt = read_packet(&mut stream)?;
    assert_eq!(hello_pkt.packet_type, PacketType::Hello);

    let login_info = if std::fs::exists(LOGIN_INFO_PATH)? {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .open(LOGIN_INFO_PATH)?;

        serde_json::from_reader::<_, LoginInfo>(f)?
    } else {
        let mut register_req = Packet {
            packet_type: PacketType::Register,
            request_id: None,
            payload: Vec::new(),
        };

        let register_resp = do_request(&mut register_req, &mut stream)?;
        assert_eq!(register_resp.packet_type, PacketType::Registered);
        let mut cursor = Cursor::new(register_resp.payload.as_slice());

        let username = read_string(&mut cursor)?;
        let password = read_string(&mut cursor)?;

        let login_info = LoginInfo { username, password };

        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(LOGIN_INFO_PATH)?;

        serde_json::to_writer_pretty::<_, LoginInfo>(f, &login_info)?;

        login_info
    };

    let mut cursor = Cursor::new(Vec::new());

    write_string(&mut cursor, &login_info.username)?;
    write_string(&mut cursor, &login_info.password)?;

    let mut login_req = Packet {
        packet_type: PacketType::Login,
        request_id: None,
        payload: cursor.into_inner(),
    };

    let _login_resp = do_request(&mut login_req, &mut stream)?;
    assert_eq!(_login_resp.packet_type, PacketType::Result);

    Ok(())
}
