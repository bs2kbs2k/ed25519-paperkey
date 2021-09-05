use std::io::Write;
use zeroize::Zeroize;

fn main() -> anyhow::Result<()> {
    let wordlist = include_str!("wordlist.txt")
        .split_whitespace()
        .collect::<Vec<_>>();
    let args = clap::App::new("ed25519 paper key generator/decoder")
        .arg(clap::Arg::with_name("decode").short("d"))
        .arg(clap::Arg::with_name("filename").required(true).index(1))
        .get_matches();
    if args.is_present("decode") {
        let mut code = String::new();
        std::io::stdin().read_line(&mut code);
        let mut code = code
            .split_whitespace()
            .map(|word| {
                wordlist
                    .binary_search(&word)
                    .map_err(|err| anyhow::anyhow!("Invalid word"))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut bitidx: u8 = 0;
        let mut key = [0_u8; 32];
        'outer: for num in &code {
            for offset in 0..11 {
                key[(bitidx / 8) as usize] <<= 1;
                key[(bitidx / 8) as usize] |= ((num >> (10 - offset)) & 1) as u8;
                if bitidx == 255 {
                    break 'outer;
                }
                bitidx += 1;
            }
        }
        let secretkey = ed25519_dalek::SecretKey::from_bytes(key.as_ref())?;
        key.zeroize();
        code.zeroize();
        let pubkey = ed25519_dalek::PublicKey::from(&secretkey);
        let mut file = std::fs::File::create(args.value_of("filename").unwrap())?;
        file.write_all("-----BEGIN OPENSSH PRIVATE KEY-----\n".as_ref())?;
        let mut writer = base64::write::EncoderWriter::new(file, base64::STANDARD);
        writer.write_all(include_bytes!("header.bin"))?;
        writer.write_all(pubkey.as_ref())?;
        writer.write_all(include_bytes!("middle1.bin"))?;
        writer.write_all(pubkey.as_ref())?;
        writer.write_all(include_bytes!("middle2.bin"))?;
        writer.write_all(secretkey.as_ref())?;
        writer.write_all(pubkey.as_ref())?;
        writer.write_all(include_bytes!("tail.bin"))?;
        let mut file = writer.finish()?;
        file.write_all("\n-----END OPENSSH PRIVATE KEY-----".as_ref())?;
    } else {
        let mut file = std::fs::read_to_string(args.value_of("filename").unwrap())?;
        let thrussh_keys::key::KeyPair::Ed25519(key) =
            thrussh_keys::decode_secret_key(file.as_str(), None)?;
        let key: Vec<u8> = key.key[..32].into();
        let mut encoded_key: Vec<&str> = vec![];
        let mut word: u16 = 0;
        let mut wordoffset: u8 = 0;
        for byte in key {
            for offset in 0..8 {
                word |= ((byte >> (7 - offset)) & 1) as u16;
                word <<= 1;
                wordoffset += 1;
                if wordoffset == 11 {
                    word >>= 1;
                    encoded_key.push(wordlist[word as usize]);
                    word = 0;
                    wordoffset = 0;
                }
            }
        }
        word <<= 7;
        encoded_key.push(wordlist[word as usize]);
        println!("{}", encoded_key.join(" "));
    }
    Ok(())
}
