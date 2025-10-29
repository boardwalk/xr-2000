#![feature(hash_set_entry)]
use anyhow::{Error, anyhow, bail};
use bitfields::bitfield;
use byteorder::{LittleEndian, ReadBytesExt as _, WriteBytesExt as _};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::ToSocketAddrs as _;
use std::thread::sleep;
use std::time::Duration;

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

#[derive(Clone, Copy, Debug)]
enum RequestResult {
    Success,
    AlreadyAuthenticated,
    NotAuthenticated,
    InvalidCredentials,
    NotAuthorizedForTransceiverUsage,
    TranslationLimiting,
    ConfigureMalfunction,
    InvalidConfigParameter,
    TransceiverNotConfigured,
    RouteMalfunction,
    MailNotFound,
    RecipientUsernameNotFound,
    TranslationNotFound,
}
impl TryFrom<u8> for RequestResult {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use RequestResult::*;

        let val = match value {
            0x00 => Success,
            0x01 => AlreadyAuthenticated,
            0x02 => NotAuthenticated,
            0x03 => InvalidCredentials,
            0x05 => NotAuthorizedForTransceiverUsage,
            0x23 => TranslationLimiting,
            0x20 => ConfigureMalfunction,
            0x21 => InvalidConfigParameter,
            0x24 => TransceiverNotConfigured,
            0x25 => RouteMalfunction,
            0x40 => MailNotFound,
            0x41 => RecipientUsernameNotFound,
            0x50 => TranslationNotFound,
            _ => bail!("invalid request result"),
        };

        Ok(val)
    }
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

#[bitfield(u8, order = msb)]
struct PacketHeader {
    #[bits(2)]
    lfl: u8,
    has_request_id: bool,
    #[bits(5)]
    packet_type: u8,
}

#[bitfield(u8)]
struct StatusFlags {
    #[bits(1)]
    authenticated: bool,
    #[bits(1)]
    transceiver_authorized: bool,

    #[bits(1)]
    transceiver_configured: bool,
    #[bits(5)]
    _pad: u8,
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
    let header = PacketHeader::from_bits(stream.read_u8()?);

    let request_id = if header.has_request_id() {
        Some(stream.read_u8()?)
    } else {
        None
    };
    let magic = stream.read_u32::<LittleEndian>()?;

    if magic != MAGIC {
        bail!("invalid magic")
    }

    let packet_type = PacketType::try_from(header.packet_type())?;

    let payload_len = match header.lfl() {
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

    let header = PacketHeaderBuilder::new()
        .with_has_request_id(pkt.request_id.is_some())
        .with_lfl(lfl)
        .with_packet_type(u8::from(pkt.packet_type))
        .build();

    stream.write_all(&[header.into_bits()])?;

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

#[derive(Debug)]
struct Mail {
    mail_id: u32,
    timestamp: u32,
    sender: String,
    content: String,
}

enum Modulation {
    AM,
    FM,
    PM,
    BPSK,
}

impl From<Modulation> for u8 {
    fn from(value: Modulation) -> Self {
        match value {
            Modulation::AM => 0x00,
            Modulation::FM => 0x01,
            Modulation::PM => 0x02,
            Modulation::BPSK => 0x03,
        }
    }
}

struct Configuration {
    frequency: u32,
    baud_rate: u32,
    modulation: Modulation,
}

struct Client {
    stream: TcpStream,
    login_info: Option<LoginInfo>,
    num_mails: u32,
    mail: HashMap<u32, Mail>,
}

impl Client {
    fn new() -> Result<Self, Error> {
        let addr = ADDR
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("addr didn't resolve to any addresses"))?;

        let mut stream = TcpStream::connect(addr)?;

        let hello_pkt = read_packet(&mut stream)?;
        assert_eq!(hello_pkt.packet_type, PacketType::Hello);

        Ok(Self {
            stream,
            login_info: None,
            num_mails: 0,
            mail: HashMap::new(),
        })
    }

    fn load_login_info(&mut self) -> Result<bool, Error> {
        if std::fs::exists(LOGIN_INFO_PATH)? {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .open(LOGIN_INFO_PATH)?;

            self.login_info = Some(serde_json::from_reader::<_, LoginInfo>(f)?);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn save_login_info(&mut self) -> Result<(), Error> {
        let Some(login_info) = &self.login_info else {
            bail!("no login info to save");
        };

        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(LOGIN_INFO_PATH)?;

        serde_json::to_writer_pretty::<_, LoginInfo>(f, login_info)?;
        Ok(())
    }

    fn do_request(&mut self, req: &mut Packet) -> Result<Packet, Error> {
        req.request_id = Some(rand::random::<u8>());

        write_packet(&mut self.stream, req)?;

        loop {
            let resp = read_packet(&mut self.stream)?;

            if resp.packet_type == PacketType::Status {
                let mut cursor = Cursor::new(&resp.payload);

                let num_mails = cursor.read_u32::<LittleEndian>()?;
                let conn_time = cursor.read_u32::<LittleEndian>()?;

                let status_flags = StatusFlags::from_bits(cursor.read_u8()?);

                println!(
                    "got status with num_mails = {num_mails}, conn_time = {conn_time}, status_flags = {status_flags:?}"
                );

                self.num_mails = num_mails;

                continue;
            }

            if resp.packet_type == PacketType::Result {
                let mut cursor = Cursor::new(&resp.payload);

                let rr = RequestResult::try_from(cursor.read_u8()?)?;

                if !matches!(rr, RequestResult::Success) {
                    bail!("request failed: {rr:?}");
                }
            }

            if resp.request_id != req.request_id {
                bail!("mismatched request_id");
            }

            return Ok(resp);
        }
    }

    fn login(&mut self) -> Result<(), Error> {
        let mut cursor = Cursor::new(Vec::new());

        let Some(login_info) = self.login_info.as_ref() else {
            bail!("no login info to use");
        };

        write_string(&mut cursor, &login_info.username)?;
        write_string(&mut cursor, &login_info.password)?;

        let mut login_req = Packet {
            packet_type: PacketType::Login,
            request_id: None,
            payload: cursor.into_inner(),
        };

        let _login_resp = self.do_request(&mut login_req)?;
        assert_eq!(_login_resp.packet_type, PacketType::Result);

        Ok(())
    }

    fn register(&mut self) -> Result<(), Error> {
        let mut register_req = Packet {
            packet_type: PacketType::Register,
            request_id: None,
            payload: Vec::new(),
        };

        let register_resp = self.do_request(&mut register_req)?;
        assert_eq!(register_resp.packet_type, PacketType::Registered);
        let mut cursor = Cursor::new(register_resp.payload.as_slice());

        let username = read_string(&mut cursor)?;
        let password = read_string(&mut cursor)?;

        self.login_info = Some(LoginInfo { username, password });

        Ok(())
    }

    fn fetch_mail(&mut self, req_mail_id: u32) -> Result<(), Error> {
        if self.mail.contains_key(&req_mail_id) {
            return Ok(());
        }

        let mut cursor = Cursor::new(Vec::new());

        cursor.write_u32::<LittleEndian>(req_mail_id)?;
        let mut get_mail_req = Packet {
            packet_type: PacketType::GetMail,
            request_id: None,
            payload: cursor.into_inner(),
        };

        let get_mail_resp = self.do_request(&mut get_mail_req)?;
        assert_eq!(get_mail_resp.packet_type, PacketType::Mail);

        let mut cursor = Cursor::new(get_mail_resp.payload);

        let resp_mail_id = cursor.read_u32::<LittleEndian>()?;
        assert_eq!(resp_mail_id, req_mail_id);

        let timestamp = cursor.read_u32::<LittleEndian>()?;
        let sender = read_string(&mut cursor)?;

        let content_len = cursor.read_u32::<LittleEndian>()?;

        let mut content = vec![0; content_len as usize];

        cursor.read_exact(&mut content)?;
        let content = String::from_utf8(content)?;

        std::fs::write(format!("mail_{resp_mail_id}.txt"), &content)?;

        self.mail.insert(
            resp_mail_id,
            Mail {
                mail_id: resp_mail_id,
                timestamp,
                sender,
                content,
            },
        );

        Ok(())
    }

    fn get_mail(&mut self, mail_id: u32) -> Result<&Mail, Error> {
        let Some(mail) = self.mail.get(&mail_id) else {
            bail!("No such mail");
        };

        Ok(mail)
    }

    fn get_new_mail(&mut self) -> Result<(), Error> {
        for i in 0..self.num_mails {
            self.fetch_mail(i + 1)?;
        }

        Ok(())
    }

    fn configure(&mut self, configuration: Configuration) -> Result<(), Error> {
        let mut cursor = Cursor::new(Vec::new());

        cursor.write_u32::<LittleEndian>(configuration.frequency)?;
        cursor.write_u32::<LittleEndian>(configuration.baud_rate)?;

        cursor.write_u8(configuration.modulation.into())?;

        let mut configure_req = Packet {
            packet_type: PacketType::Configure,
            request_id: None,
            payload: cursor.into_inner(),
        };

        let configure_resp = self.do_request(&mut &mut configure_req)?;

        assert_eq!(configure_resp.packet_type, PacketType::Result);

        Ok(())
    }

    // translate rasvakian to atlantian
    fn translate(&mut self, rasvakian: &str) -> Result<String, Error> {
        let mut translate_res = Packet {
            packet_type: PacketType::Translate,
            request_id: None,
            payload: rasvakian.to_ascii_lowercase().into_bytes(),
        };

        let translate_resp = self.do_request(&mut translate_res)?;

        assert_eq!(translate_resp.packet_type, PacketType::Translation);

        let atlantian = String::from_utf8(translate_resp.payload)?.to_ascii_lowercase();

        Ok(atlantian)
    }
}

fn main() -> Result<(), Error> {
    let mut client = Client::new()?;
    if !client.load_login_info()? {
        client.register()?;
        client.save_login_info()?;
    }

    client.login()?;
    client.fetch_mail(1)?;
    client.fetch_mail(2)?;
    let ciphertext = client.get_mail(2)?.content.to_ascii_lowercase();

    println!("ciphertext = {ciphertext}");

    let word_match = regex::Regex::new("[a-z]+")?;

    let mut words = HashSet::new();

    for m in word_match.find_iter(&ciphertext) {
        words.get_or_insert_with(m.as_str(), |s| s.to_owned());
    }

    let mut translations = HashMap::new();

    for (word_i, rasvakian) in words.iter().enumerate() {
        println!("working on {} of {}", word_i, words.len());

        let atlantian = client.translate(rasvakian)?;

        client.get_new_mail()?;

        translations.insert(rasvakian.to_string(), atlantian);

        sleep(Duration::from_millis(1100));
    }

    let plaintext = word_match
        .replace_all(&ciphertext, |captures: &regex::Captures| {
            if let Some(translation) = translations.get(&captures[0]) {
                translation.to_owned()
            } else {
                captures[0].to_owned()
            }
        })
        .into_owned();

    println!("{plaintext}");

    Ok(())
}
