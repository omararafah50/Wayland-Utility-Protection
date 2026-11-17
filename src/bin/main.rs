//importing libraries via 'use' by rust
use nix::sys::signal::{self, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::{close, fork, pipe, read, write, ForkResult, Pid};
use rand::Rng;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

const PRIME: u64 = 2147483647;
const SOCKET_PATH: &str = "/tmp/secbroker.sock";

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveBuffer {
    data: Vec<u64>,
}

struct Worker {
    pid: Pid,
    main_to_worker_write: OwnedFd,
    worker_to_main_read: OwnedFd,
    x_id: u64,
}

struct DaemonState {
    workers: Vec<Worker>,
    threshold_k: usize,
}

static STATE: Mutex<Option<DaemonState>> = Mutex::new(None);
static RUNNING: AtomicBool = AtomicBool::new(true);

fn sigma_polynomial(coefficients: &[u64], x: u64) -> u64 {
    let mut result = 0u128;
    let mut x_pow = 1u128;
    let prime = PRIME as u128;

    for &coeff in coefficients {
        let term = ((coeff as u128) * x_pow) % prime;
        result = (result + term) % prime;
        x_pow = (x_pow * (x as u128)) % prime;
    }
    (result % prime) as u64
}

fn mod_inverse(a: u64) -> u64 {
    let m = PRIME as u128;
    let mut exp = m - 2;
    let mut result = 1u128;
    let mut base = (a as u128) % m;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % m;
        }
        base = (base * base) % m;
        exp /= 2;
    }
    result as u64
}

fn reconstruct_secret(x_vals: &[u64], y_vals: &[u64]) -> u64 {
    let k = x_vals.len();
    let prime = PRIME as u128;
    let mut secret = 0u128;

    for i in 0..k {
        let mut numerator = 1u128;
        let mut denominator = 1u128;

        for j in 0..k {
            if i == j {
                continue;
            }

            let xj = x_vals[j] as u128;
            let xi = x_vals[i] as u128;

            numerator = (numerator * (prime - xj)) % prime;

            let diff = if xi >= xj {
                xi - xj
            } else {
                prime - (xj - xi)
            };
            denominator = (denominator * (diff % prime)) % prime;
        }

        let lagrange_coeff = (numerator * mod_inverse(denominator as u64) as u128) % prime;
        let term = ((y_vals[i] as u128) * lagrange_coeff) % prime;
        secret = (secret + term) % prime;
    }

    (secret % prime) as u64
}

fn run_worker_loop(read_fd: RawFd, write_fd: RawFd) {
    let mut reader = unsafe { File::from_raw_fd(read_fd) };
    let mut writer = unsafe { File::from_raw_fd(write_fd) };

    let mut share_bytes = [0u8; 8];

    if reader.read_exact(&mut share_bytes).is_err() {
        exit(1);
    }

    let mut share = u64::from_ne_bytes(share_bytes);
    let mut cmd = [0u8; 1];

    while reader.read_exact(&mut cmd).is_ok() {
        match cmd[0] {
            b'F' => {
                let bytes_to_send = share.to_ne_bytes();
                if writer.write_all(&bytes_to_send).is_err() {
                    break;
                }
            }
            b'Q' => break,
            _ => {}
        }
    }

    share.zeroize();
    exit(0);
}

fn store_secret(secret_val: u64, n: usize, k: usize) {
    cleanup_existing_workers();

    let mut rng = rand::thread_rng();

    let mut coeffs = SensitiveBuffer {
        data: vec![0u64; k],
    };

    coeffs.data[0] = secret_val % PRIME;
    for i in 1..k {
        coeffs.data[i] = rng.gen_range(0..PRIME);
    }

    let mut new_workers = Vec::with_capacity(n);

    for i in 0..n {
        let x_id = (i + 1) as u64;

        let (m2w_r, m2w_w): (OwnedFd, OwnedFd) = pipe().unwrap();
        let (w2m_r, w2m_w): (OwnedFd, OwnedFd) = pipe().unwrap();

        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                drop(m2w_w);
                drop(w2m_r);
                run_worker_loop(m2w_r.as_raw_fd(), w2m_w.as_raw_fd());
            }
            Ok(ForkResult::Parent { child }) => {
                drop(m2w_r);
                drop(w2m_w);

                let share = sigma_polynomial(&coeffs.data, x_id);
                let _ = write(&m2w_w, &share.to_ne_bytes());

                new_workers.push(Worker {
                    pid: child,
                    main_to_worker_write: m2w_w,
                    worker_to_main_read: w2m_r,
                    x_id,
                });
            }
            Err(e) => panic!("Fork failed: {}", e),
        }
    }

    let mut guard = STATE.lock().unwrap();
    *guard = Some(DaemonState {
        workers: new_workers,
        threshold_k: k,
    });

    println!("Secret distributed across {} workers (Rust RAM zeroized)!", n);
}

fn handle_client(mut stream: UnixStream) {
    let mut buffer = [0u8; 1024];
    let bytes_read = match stream.read(&mut buffer) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);

    if request.starts_with("STORE ") {
        if let Ok(secret_val) = request[6..].trim().parse::<u64>() {
            store_secret(secret_val, 5, 3);
            let _ = stream.write_all(b"TOKEN_SUCCESS_9F82\n");
        }
    } else if request.starts_with("FETCH") {
        let guard = STATE.lock().unwrap();

        if let Some(ref state) = *guard {
            let k = state.threshold_k;

            let mut x_vals = SensitiveBuffer { data: vec![0u64; k] };
            let mut y_vals = SensitiveBuffer { data: vec![0u64; k] };

            for i in 0..k {
                let cmd = [b'F'];
                let worker = &state.workers[i];

                let _ = write(&worker.main_to_worker_write, &cmd);
                x_vals.data[i] = worker.x_id;

                let mut y_bytes = [0u8; 8];
                let _ = read(worker.worker_to_main_read.as_raw_fd(), &mut y_bytes);
                y_vals.data[i] = u64::from_ne_bytes(y_bytes);
            }

            let mut reconstructed = reconstruct_secret(&x_vals.data, &y_vals.data);

            let response = format!("SECRET: {}\n", reconstructed);
            let _ = stream.write_all(response.as_bytes());

            reconstructed.zeroize();
        } else {
            let _ = stream.write_all(b"ERROR: No secret stored\n");
        }
    }
}

fn cleanup_existing_workers() {
    let mut guard = STATE.lock().unwrap();
    if let Some(mut state) = guard.take() {
        for worker in state.workers.iter_mut() {
            let cmd = [b'Q'];
            let _ = write(&worker.main_to_worker_write, &cmd);
            let _ = waitpid(worker.pid, None);
        }
    }
}

fn cleanup() {
    cleanup_existing_workers();
    let _ = fs::remove_file(SOCKET_PATH);
    println!("\nDaemon terminated cleanly.");
}

fn main() {
    let _ = fs::remove_file(SOCKET_PATH);

    unsafe {
        let _ = signal::signal(Signal::SIGINT, signal::SigHandler::Handler(handle_sig));
        let _ = signal::signal(Signal::SIGTERM, signal::SigHandler::Handler(handle_sig));
    }

    let listener = UnixListener::bind(SOCKET_PATH).expect("Failed to bind socket");
    println!("Listening at {}", SOCKET_PATH);

    for stream in listener.incoming() {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }

        match stream {
            Ok(stream) => handle_client(stream),
            Err(_) => break,
        }
    }

    cleanup();
}

extern "C" fn handle_sig(_: i32) {
    RUNNING.store(false, Ordering::SeqCst);
    cleanup();
    exit(0);
}
