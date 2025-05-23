use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn handle_client(mut stream: TcpStream) {
    loop {
        let mut buffer = [0; 512];
        stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..]);

        println!("Received request: {}", request);

        if request.trim() == "exit" {
            break;
        }

        let response = "HTTP/1.1 200 OK\n\nHello, world!";
        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
}

pub fn launch() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Failed to establish a connection: {}", e);
            }
        }
    }
}
