//Nix is a crate that lets rust talk to unix operating systems like creating processes, pipes and
//signals
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
//Zeroize is a trait that sets a variables ram to 0 when it goes out of scope
use zeroize::{Zeroize, ZeroizeOnDrop};

const PRIME: u64 = 2147483647;
const SOCKET_PATH: &str = "/tmp/secbroker.sock";


//gives behaviour to sensitive buffer such as methods like .zeroize()
#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveBuffer {
    data: Vec<u64>,
}

//holds a single worker instance's data such as its process id, its pipes and unique x id
struct Worker {
    pid: Pid,
    main_to_worker_write: OwnedFd,
    worker_to_main_read: OwnedFd,
    x_id: u64,
}

//holds all the running workers in a vector and has the k threshold
struct DaemonState {
    workers: Vec<Worker>,
    threshold_k: usize,
}

//const vs static, const: is inline, it doesnt have a memory address, no ram, when u refer to it it
//just substitutes its actual value, a static has actual space in ram and can be editable which is
//dangerous since multiple things might edit it.
//now to prevent the static error, u can implement a mutex, a mutex basically takes a value and
//locks it, when u access u unlock and re lock and etc, this prevents multiple threads from tryna
//access it and cuase errors, you lock and once you try to unlock and theres an existing operation,
//you wait until it gets unlocked, here we define it as none because we define it initially later
static STATE: Mutex<Option<DaemonState>> = Mutex::new(None);
//atomics are basically universal, usually, you define a variable, however its changes remain
//inconsistent across threads, so to enforce universality, we use atomics, one type is atomic bool,
//which baisclaly sets an atomicbool, later when we edit it, we change its value with specific
//ordering
static RUNNING: AtomicBool = AtomicBool::new(true);

fn sigma_polynomial(coefficients: &[u64], x: u64) -> u64 {
    let mut result = 0u128;
    let mut x_pow = 1u128;
    let prime = PRIME as u128;

    for &coeff in coefficients {
        //In rust, type is strict, so you cant multiply a u32 integer by a u64 integer, it wil lcaue
        //an error, so we use "as <T>" which converts the number to a type to perform operations,
        //example where we wana multiply x which is u32 and y which is u64 we do x * (y as u32), 
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
    //
    let mut reader = unsafe { File::from_raw_fd(read_fd) };
    let mut writer = unsafe { File::from_raw_fd(write_fd) };

    let mut share = 0u64;
    let mut cmd = [0u8; 1];
    //cmd is just 0 rn, so when we do read_exact(k) where k is the variable to write the data to, we
    //use a mutable reference to it to ptu whateeer was read there
    while reader.read_exact(&mut cmd).is_ok() {
        match cmd[0] {
            //'S' is a rust character but doing b'S', gives u a u8 that is an ascii code for the
            //letter S that we use to communicate in pipes
            b'S' => {
                let mut share_bytes = [0u8; 8];
                if reader.read_exact(&mut share_bytes).is_err() {
                    break;
                }
                share = u64::from_ne_bytes(share_bytes);
            }
            b'F' => {
                //in ipc, you can only send down bytes, u8, which is 8 bits, one byte, it doesnt
                //know u32 or u64, so to break it down u use to ne bytes which breaks it down into
                //an array of 8 elements each u8, (one byte) that can get digested by the pipe, then
                //when the array arrives to other end we use from_ne_nytes to re convert it into u64
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

fn spawn_workers(n: usize, k: usize) -> DaemonState {
    let mut workers = Vec::with_capacity(n);

    for i in 0..n {
        let x_id = (i + 1) as u64;
        //We create 2 pipes for each worker (to send data to parent, and parent send data back)
        //Unlike in C where fd is an integer which requires closing, in rust, ownedfd closes
        //automatically when out of scope
        //OwnedFd is just a struct with a zeroize / drop trait on it that means it gets deleted when
        //out of scope when we drop it, and it is more safer cause its a struct
        let (m2w_r, m2w_w): (OwnedFd, OwnedFd) = pipe().unwrap();
        let (w2m_r, w2m_w): (OwnedFd, OwnedFd) = pipe().unwrap();

        match unsafe { fork() } {
            //Ok is a tuple variant of an enum, it just marks things as successful, fork returns 2
            //things the forkresult::Child pov and forkresut parent pov, and it also returns ok and
            //err if it detects error, we use this here to extract data via patternm atching
            Ok(ForkResult::Child) => {
                drop(m2w_w);
                drop(w2m_r);
                //drop closes the filedescriptors, typically, m2w_w is main to worker write, so it mains main
                //daemon writes to worker, and w2m_r which is worker to main read which means the
                //daemon (main) reads from worker, which it has no business dealing with, so we
                //close these to ensure safety
                unsafe {
                    //calls prctl to prevent worker processes from reading each other's ram, if the
                    //return is non zero (failure exit code) it exits
                    if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                        eprintln!("Failed to set PR_SET_DUMPABLE");
                        exit(1);
                    }
                };
                //as raw fd sends the numerical file descriptor
                run_worker_loop(m2w_r.as_raw_fd(), w2m_w.as_raw_fd());
            }
            //using rust destructuring (parent holds the hcild pid in struct variant)
            Ok(ForkResult::Parent { child }) => {
                drop(m2w_r);
                drop(w2m_w);

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

    DaemonState {
        workers,
        threshold_k: k,
    }
}

fn store_secret(secret_val: u64, n: usize, k: usize) {
    //we take guard from mutex, it returns Option<Daemonstate>
    let guard = STATE.lock().unwrap();
    let state = match *guard {
        //ref is different in pattern matching, when we do & instead of ref, we are literally
        //matching and seeing if guard is a reference which isnt, but when we do ref WE ARE TAKING a
        //reference, not checking / matching if it is one
        Some(ref s) => s,
        None => return,
    };

    // use csprng 
    let mut rng = rand::thread_rng();
    
    //storing ocefficients in sensitive buffer that zeroizes when out of scope, the vector holds up
    //to k elements
    let mut coeffs = SensitiveBuffer {
        data: vec![0u64; k],
    };

    coeffs.data[0] = secret_val % PRIME;
    for i in 1..k {
        coeffs.data[i] = rng.gen_range(1..PRIME); 
    }
 
    for worker in &state.workers {
        let share = sigma_polynomial(&coeffs.data, worker.x_id);
        let mut msg = vec![b'S'];
        msg.extend_from_slice(&share.to_ne_bytes());
        //write just sends data down the pipe, its different from write_all, writeall is a method
        //accessible when we wrap a file descriptor in a file, in IPC and in unix, everything is a
        //file, a pipe is a file, using write() however poses problems because some bytes can be
        //left behind and we need to manually do a while loop to handle the remaining bytes,
        //wrapping a file descriptor via File however, we bypass this as we get access to a method
        //like write_all which handles that loop for you, making write only good for small things
        let _ = write(&worker.main_to_worker_write, &msg);
    }

    println!("Secret distributed across {} workers (Rust RAM zeroized)!", n);
    //coeffs goes out of scope, zeroize deletes it
}

//unixstream is bidirectional by default, it represents a connection between client and daemon
fn handle_client(mut stream: UnixStream) {
    let mut buffer = [0u8; 1024];
    let bytes_read = match stream.read(&mut buffer) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    //utf8 stores every character A-Z as 1 byte, each 1 byte corresponding to its actual value
    //we can technically comment this out and use b'' to convert strings to bytes for comparisons,
    //however utf8 lossy also works!
    //in an array, we can slice like this: let x: [i32;5] = y[0..6], we use 6 because its excluded,
    //we can also include the rest like y[0..n] or [n..] or [..n] for up to a specific point
    if request.starts_with("STORE ") {
        //::<T> is turbofish, works with generics, it tells rust specifically what the type is
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
        for worker in state.workers.iter_mut() { //when doing for loop on vectors, we have to burrow
                                                 //it, but here we can also use iter() or iter_mut()
                                                 //which do &mut and & as shortcuts
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
    //stale socket removal
    let _ = fs::remove_file(SOCKET_PATH);
    

    //create signals for sigterm and exits
    unsafe {
        let _ = signal::signal(Signal::SIGINT, signal::SigHandler::Handler(handle_sig));
        let _ = signal::signal(Signal::SIGTERM, signal::SigHandler::Handler(handle_sig));
    }

    // SPAWN WORKERS ONCE AT STARTUP BEFORE ANY SECRETS EXIST IN MEMORY
    let initial_state = spawn_workers(5, 3);
    //we define {} here to define a new scope that goes out of scope and guard deletes automatically
    //which would prevent blockages, here we create the INITIAL mutex / guard
    //unwrap just takes the value inside, basically, a mutex can bep poisioned, that is an operaiton
    //mid way crashes and the mutex is corrupted, so we use unwrap to take a value
    {
        let mut guard = STATE.lock().unwrap();
        *guard = Some(initial_state);
    }

    let listener = UnixListener::bind(SOCKET_PATH).expect("Failed to bind socket"); //starts
                                                                                    //listener on
                                                                                    //socket,
                                                                                    //.expect falls
                                                                                    //back to an
                                                                                    //error if
                                                                                    //anything
                                                                                    //happens
    println!("Listening at {}", SOCKET_PATH);

    for stream in listener.incoming() {
        if !RUNNING.load(Ordering::SeqCst) { //Orderings are the way the atomics are loaded, SeqCst
                                             //is the safest and most secure as it prevents any race
                                             //conditions
            break;
        }

        match stream {
            Ok(stream) => handle_client(stream),
            Err(_) => break,
        }
    }

    cleanup();
}

//since linux is written almost fully in C and most modern programming languages are in C, when we
//exit via ctrl C, the kernel looks and tries to execute this but since its in C, it expects it in
//C, so it cant do it so we have to use extern "C" which means it gets compiled into machine code
//that follows C 
extern "C" fn handle_sig(_: i32) {
    RUNNING.store(false, Ordering::SeqCst);
    cleanup();
    exit(0);
}
