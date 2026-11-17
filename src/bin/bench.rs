use nix::sys::wait::waitpid;
use nix::unistd::{fork, pipe, read, write, ForkResult, Pid};
use rand::Rng;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::exit;
use std::time::Instant;
use zeroize::{Zeroize, ZeroizeOnDrop};


const PRIME: u64 = 2147483647;

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

fn main() {
    let iterations = 1000;
    let share_counts = vec![5, 10, 25, 50, 100];

    println!("==========================================================================");
    println!("  EMPIRICAL BENCHMARK: SSS DAEMON PROCESS ISOLATION (N={} TRIALS)", iterations);
    println!("==========================================================================");
    println!("{:<8} | {:<18} | {:<18} | {:<10} | {:<10}", "Shares", "Split Mean ± σ", "Reconstruct Mean", "P50 (µs)", "P99 (µs)");
    println!("--------------------------------------------------------------------------");

    for &n in &share_counts {
        let k = (n / 2) + 1; // Threshold k = ceil(n/2)

        let mut split_times_us: Vec<f64> = Vec::with_capacity(iterations);
        let mut recon_times_us: Vec<f64> = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let secret_val: u64 = 987654321;

            // --- 1. Benchmark Split & Worker Distribution ---
            let start_split = Instant::now();

            let mut rng = rand::thread_rng();
            let mut coeffs = SensitiveBuffer {
                data: vec![0u64; k],
            };
            coeffs.data[0] = secret_val % PRIME;
            for i in 1..k {
                coeffs.data[i] = rng.gen_range(0..PRIME);
            }

            let mut workers = Vec::with_capacity(n);

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

                        workers.push(Worker {
                            pid: child,
                            main_to_worker_write: m2w_w,
                            worker_to_main_read: w2m_r,
                            x_id,
                        });
                    }
                    Err(e) => panic!("Fork failed: {}", e),
                }
            }
            let split_duration = start_split.elapsed().as_secs_f64() * 1_000_000.0;
            split_times_us.push(split_duration);

            // --- 2. Benchmark Reconstruction over IPC ---
            let start_recon = Instant::now();

            let mut x_vals = SensitiveBuffer { data: vec![0u64; k] };
            let mut y_vals = SensitiveBuffer { data: vec![0u64; k] };

            for i in 0..k {
                let cmd = [b'F'];
                let worker = &workers[i];

                let _ = write(&worker.main_to_worker_write, &cmd);
                x_vals.data[i] = worker.x_id;

                let mut y_bytes = [0u8; 8];
                let _ = read(worker.worker_to_main_read.as_raw_fd(), &mut y_bytes);
                y_vals.data[i] = u64::from_ne_bytes(y_bytes);
            }

            let mut reconstructed = reconstruct_secret(&x_vals.data, &y_vals.data);
            reconstructed.zeroize();

            let recon_duration = start_recon.elapsed().as_secs_f64() * 1_000_000.0;
            recon_times_us.push(recon_duration);

            // --- Cleanup Workers ---
            for worker in workers.iter_mut() {
                let cmd = [b'Q'];
                let _ = write(&worker.main_to_worker_write, &cmd);
                let _ = waitpid(worker.pid, None);
            }
        }

        // --- Calculate Statistics ---
        split_times_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
        recon_times_us.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let split_mean: f64 = split_times_us.iter().sum::<f64>() / iterations as f64;
        let split_var: f64 = split_times_us.iter().map(|t| (t - split_mean).powi(2)).sum::<f64>() / iterations as f64;
        let split_std_dev = split_var.sqrt();

        let recon_mean: f64 = recon_times_us.iter().sum::<f64>() / iterations as f64;
        let recon_var: f64 = recon_times_us.iter().map(|t| (t - recon_mean).powi(2)).sum::<f64>() / iterations as f64;
        let recon_std_dev = recon_var.sqrt();

        let split_p50 = split_times_us[iterations / 2];
        let split_p99 = split_times_us[(iterations as f64 * 0.99) as usize];

        println!(
            "{:<8} | {:.1} ± {:.1} µs     | {:.1} ± {:.1} µs     | {:<10.1} | {:<10.1}",
            n, split_mean, split_std_dev, recon_mean, recon_std_dev, split_p50, split_p99
        );
    }
    println!("==========================================================================");
}
