// This module implements the feeder-signer subcommand for TMKMS.
// It establishes a TCP connection to a feeder service and handles
// price feed signing requests using the configured KMS signing keys.

use abscissa_core::{clap::Parser, Command, Runnable};
use anyhow::{anyhow, Result};
use prost::Message;
use std::io::ErrorKind;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc,
    time::{self, interval, sleep, timeout, Duration, Instant},
};

use crate::imua::privval as pb;
use pb::oracle_stream_message::Sum;

use crate::application::APP;
use crate::{chain, prelude::*};
use tendermint::chain as tm_chain;

use std::path::PathBuf;

/// Default feeder service address
const DEFAULT_FEEDER_ADDR: &str = "127.0.0.1:8647";

/// Feeder-signer subcommand for handling price feed signing requests
/// 
/// This command connects to a feeder service via TCP and processes
/// incoming price feed signing requests by signing them with the
/// configured KMS signing keys.
#[derive(Parser, Command, Debug)]
pub struct FeederSignerCmd {
    /// Feeder service address (host:port)
    #[clap(short, long, default_value = DEFAULT_FEEDER_ADDR)]
    pub feeder_addr: String,

    /// Optional configuration file path
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// Chain ID to use for signing operations
    #[clap(long)]
    pub chain_id: String,
}

impl Runnable for FeederSignerCmd {
    fn run(&self) {
        // Load KMS configuration and register chains
        let config = APP.config();
        chain::load_config(&config).unwrap_or_else(|e| {
            status_err!("error loading configuration: {}", e);
            std::process::exit(1);
        });

        // Parse and validate the provided chain ID
        let chain_id = tm_chain::Id::try_from(self.chain_id.as_str())
            .unwrap_or_else(|e| panic!("invalid chain_id '{}': {}", self.chain_id, e));
        let chain_id_for_client = chain_id.clone();

        // Create a single-threaded Tokio runtime for async operations
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");

        let feeder_addr = self.feeder_addr.clone();

        // Run the feeder client in the async runtime
        rt.block_on(async move {
            run_feeder_client(&feeder_addr, chain_id_for_client, move |raw: &[u8]| {
                let guard = chain::REGISTRY.get();
                let chain_ref = guard
                    .get_chain(&chain_id)
                    .ok_or_else(|| anyhow!("chain '{}' missing from registry!", chain_id))?;
                chain::sign_raw_bytes(chain_ref, raw).map_err(|e| anyhow!("tmkms sign error: {e}"))
            })
            .await;
        });
    }
}

/// Main feeder client loop that handles connection and reconnection logic
/// 
/// This function establishes a TCP connection to the feeder service and
/// automatically reconnects with exponential backoff if the connection fails.
async fn run_feeder_client<S>(addr: &str, chain_id: tm_chain::Id, signer: S)
where
    S: Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync + 'static,
{
    let mut attempt: u32 = 0;
    let backoff_min = Duration::from_millis(300);
    let backoff_max = Duration::from_secs(10);

    loop {
        println!("[conn] connecting to {addr} ...");
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                // Enable TCP_NODELAY for low-latency communication
                let _ = stream.set_nodelay(true);
                println!("[conn] connected to {addr}");
                attempt = 0;

                // Run the session and handle any errors
                if let Err(e) = run_session(stream, &chain_id, &signer).await {
                    eprintln!("[conn] session ended: {e:?}");
                }
            }
            Err(e) => eprintln!("[conn] connect error: {e:?}"),
        }

        // Calculate exponential backoff for reconnection
        attempt = attempt.saturating_add(1);
        let pow = attempt.min(6);
        let mut wait = backoff_min * (1u32 << pow);
        if wait > backoff_max {
            wait = backoff_max;
        }
        println!("[conn] reconnect after {:?}", wait);
        sleep(wait).await;
    }
}

/// Handles a single TCP session with the feeder service
/// 
/// This function manages the bidirectional communication:
/// - Reads incoming messages (ping, pong, signing requests)
/// - Sends responses (pong, signatures, public keys)
/// - Maintains connection health with periodic pings
async fn run_session<S>(stream: TcpStream, chain_id: &tm_chain::Id, signer: &S) -> Result<()>
where
    S: Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync + 'static,
{
    let (mut reader, writer) = stream.into_split();

    // Single write channel to avoid concurrent writes to the TCP stream
    let (tx, mut rx) = mpsc::channel::<pb::OracleStreamMessage>(100);
    
    println!("[session] new session started");

    let write_timeout = Duration::from_secs(5);
    let mut write_task = tokio::spawn(async move {
        let mut w = writer;
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_msg_with_timeout(&mut w, &msg, write_timeout).await {
                return Err::<(), _>(e);
            }
        }
        Ok(())
    });

    // Set up periodic ping messages to keep the connection alive
    let mut ping_tick = interval(Duration::from_secs(10));
    ping_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    let read_timeout = Duration::from_secs(8);
    let idle_timeout = Duration::from_secs(30);
    let mut last_rx_at = Instant::now();
    
    // Counters for logging ping/pong health every 10 operations
    // These reset on each new session/connection
    let mut ping_count = 0u32;
    let mut pong_count = 0u32;

    loop {
        tokio::select! {
            // Send periodic ping messages
            _ = ping_tick.tick() => {
                ping_count += 1;
                if ping_count % 10 == 0 {
                    println!("[ping] ping sent to maintain connection");
                }
                let _ = tx.send(pb::OracleStreamMessage { sum: Some(Sum::Ping(pb::Ping {})) }).await;
            }

            // Check if the write task has finished or encountered an error
            wt = &mut write_task => {
                match wt {
                    Ok(Ok(())) => return Err(anyhow!("writer finished")),
                    Ok(Err(e)) => return Err(anyhow!("writer error: {e}")),
                    Err(join_err) => return Err(anyhow!("writer panicked/cancelled: {join_err}")),
                }
            }

            // Read and process incoming messages
            res = timeout(read_timeout, read_msg::<pb::OracleStreamMessage>(&mut reader)) => {
                match res {
                    Err(_) => {
                        // Check if we've been idle too long
                        if Instant::now().duration_since(last_rx_at) >= idle_timeout {
                            return Err(anyhow!("no inbound data for {:?}, treat as dead", idle_timeout));
                        }
                        continue;
                    }
                    Ok(Err(e)) => {
                        return Err(map_net_err(e));
                    }
                    Ok(Ok(msg)) => {
                        last_rx_at = Instant::now();
                        match msg.sum {
                            // Respond to ping with pong
                            Some(Sum::Ping(_)) => {
                                let _ = tx.send(pb::OracleStreamMessage {
                                    sum: Some(Sum::Pong(pb::Pong {})),
                                }).await;
                            }
                            // Log pong messages every 10 pongs to show connection health
                            Some(Sum::Pong(_)) => {
                                pong_count += 1;
                                if pong_count % 10 == 0 {
                                    println!("[pong] pong received - connection healthy");
                                }
                            }
                            // Handle price feed signing requests
                            Some(Sum::SignPriceFeedRequest(req)) => {
                                println!("[sign] received signing request ID: {}", req.id);
                                // Perform synchronous signing on the read loop thread
                                match signer(&req.raw_data) {
                                    Ok(sig) => {
                                        println!("[sign] successfully signed request ID: {} ({} bytes)", req.id, sig.len());
                                        let _ = tx.send(pb::OracleStreamMessage {
                                            sum: Some(Sum::SignPriceFeedResponse(pb::SignPriceFeedResponse {
                                                request_id: req.id,
                                                signature: sig,
                                            })),
                                        }).await;
                                    }
                                    Err(e) => {
                                        eprintln!("[sign] error: {e:?}");
                                    }
                                }
                            }
                            // Handle public key requests
                            Some(Sum::GetPubKeyRequest(req)) => {
                                println!("[pubkey] received public key request ID: {}", req.id);
                                let guard = chain::REGISTRY.get();
                                if let Some(chain_ref) = guard.get_chain(chain_id) {
                                    match chain::ed25519_public_key_bytes(chain_ref) {
                                        Ok(pk) => {
                                            println!("[pubkey] successfully retrieved public key for request ID: {} ({} bytes)", req.id, pk.len());
                                            let _ = tx.send(pb::OracleStreamMessage{
                                                sum: Some(Sum::GetPubKeyResponse(
                                                    pb::GetPubKeyResponse {
                                                        request_id: req.id,
                                                        public_key: pk,
                                                    }
                                                )),
                                            }).await;
                                        }
                                        Err(e) => eprintln!("[pubkey] error getting public key: {e:?}"),
                                    }
                                } else {
                                    eprintln!("[pubkey] chain {} not found in registry", chain_id);
                                }
                            }
                            // Log unexpected message types
                            other => {
                                eprintln!("unexpected message: {:?}", other);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Writes a Protocol Buffer message to the TCP stream with a timeout
/// 
/// This function ensures that write operations don't hang indefinitely
/// and provides proper error handling for network issues.
async fn write_msg_with_timeout<M: Message>(
    w: &mut OwnedWriteHalf,
    msg: &M,
    dur: Duration,
) -> Result<()> {
    timeout(dur, async {
        let mut buf = Vec::with_capacity(msg.encoded_len() + 10);
        msg.encode_length_delimited(&mut buf)?;
        w.write_all(&buf).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow!("write timeout"))??;
    Ok(())
}

/// Reads a Protocol Buffer message from the TCP stream
/// 
/// This function handles the length-delimited Protocol Buffer format
/// by first reading the length prefix, then the message body.
async fn read_msg<M: Message + Default>(r: &mut OwnedReadHalf) -> Result<M> {
    let len = read_varint(r).await?;
    if len == 0 {
        return Err(anyhow!("empty frame"));
    }
    let mut frame = vec![0u8; len as usize];
    r.read_exact(&mut frame).await?;
    Ok(M::decode(&*frame)?)
}

/// Reads a variable-length integer (varint) from the stream
/// 
/// Protocol Buffers use varints for encoding message lengths.
/// This function implements the standard varint decoding algorithm.
async fn read_varint(r: &mut OwnedReadHalf) -> Result<u64> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for _ in 0..10 {
        let mut b = [0u8; 1];
        r.read_exact(&mut b).await?;
        let byte = b[0];
        if byte < 0x80 {
            x |= (byte as u64) << s;
            return Ok(x);
        } else {
            x |= ((byte & 0x7F) as u64) << s;
            s += 7;
        }
    }
    Err(anyhow!("varint too long"))
}

/// Maps network errors to user-friendly error messages
/// 
/// This function categorizes common network errors and provides
/// meaningful error messages for connection-related issues.
fn map_net_err<E: Into<anyhow::Error>>(e: E) -> anyhow::Error {
    let e = e.into();
    if let Some(ioe) = e.downcast_ref::<std::io::Error>() {
        match ioe.kind() {
            ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::TimedOut
            | ErrorKind::NotConnected => return anyhow!("connection lost: {ioe}"),
            _ => {}
        }
    }
    e
}
