use std::io::{self, Read, Write};
use std::net::TcpStream;

pub fn connect_and_communicate() -> io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:7878")?;
    let mut buffer = [0; 512];

    loop {
        print!("Enter message: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim() == "exit" {
            break;
        }

        stream.write_all(input.as_bytes())?;
        let bytes_read = stream.read(&mut buffer)?;
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        println!("Server response: {}", response);
    }

    Ok(())
}
