//! HTTP accept loop with connection caps, idle timeout, and a bounded drain.
//!
//! Axum's `serve` helper does not expose hyper's header buffer or idle
//! timeout, and its graceful shutdown waits forever. This loop stops
//! accepting on shutdown, tells open connections to finish their current
//! request, then aborts whatever is still running after the drain timeout.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use futures::FutureExt;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tower::Service;
use tower::ServiceExt;

#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub max_header_bytes: usize,
    pub max_connections: usize,
    pub idle_timeout: Duration,
    pub shutdown_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// Every accepted connection finished.
    Drained,
    /// The drain timeout elapsed and remaining connections were aborted.
    TimedOut,
}

const HYPER_MIN_HEADER_BUF: usize = 8192;

pub async fn serve(
    listener: TcpListener,
    app: Router,
    opts: ServeOptions,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<ShutdownOutcome> {
    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let (signal_tx, _signal_rx) = watch::channel(());
    let slots = if opts.max_connections == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(opts.max_connections)))
    };
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (io, remote_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        if is_connection_error(&err) {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                        return Err(err);
                    }
                };
                let permit = match &slots {
                    Some(sem) => match sem.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            tasks.spawn(reject_busy(io));
                            continue;
                        }
                    },
                    None => None,
                };
                handle_connection(
                    &mut make_service,
                    &signal_tx,
                    &opts,
                    &mut tasks,
                    io,
                    remote_addr,
                    permit,
                )
                .await;
            }
        }
    }

    drop(signal_tx);
    drop(listener);

    let outcome = tokio::select! {
        _ = drain(&mut tasks) => ShutdownOutcome::Drained,
        _ = tokio::time::sleep(opts.shutdown_timeout) => {
            tasks.abort_all();
            ShutdownOutcome::TimedOut
        }
    };
    Ok(outcome)
}

async fn drain(tasks: &mut JoinSet<()>) {
    while tasks.join_next().await.is_some() {}
}

fn is_connection_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

async fn handle_connection(
    make_service: &mut IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
    signal_tx: &watch::Sender<()>,
    opts: &ServeOptions,
    tasks: &mut JoinSet<()>,
    io: TcpStream,
    remote_addr: SocketAddr,
    permit: Option<OwnedSemaphorePermit>,
) {
    let io = TokioIo::new(io);
    let tower_service = Service::call(make_service, remote_addr)
        .await
        .unwrap_or_else(|err| match err {})
        .map_request(|request: Request<Incoming>| request.map(Body::new));

    let hyper_service = TowerToHyperService::new(tower_service);
    let signal_tx = signal_tx.clone();
    let opts = opts.clone();
    tasks.spawn(async move {
        let _permit = permit;
        // HTTP/1 only. The auto builder waits for bytes to sniff HTTP/2, so a
        // silent connection would never arm the header/idle timeout.
        let mut builder = Builder::new(TokioExecutor::new()).http1_only();
        let idle = if opts.idle_timeout.is_zero() {
            None
        } else {
            Some(opts.idle_timeout)
        };
        builder
            .http1()
            .timer(TokioTimer::default())
            .header_read_timeout(idle)
            .max_buf_size(opts.max_header_bytes.max(HYPER_MIN_HEADER_BUF));
        // `serve_connection` honors `http1_only`. The upgradable variant always
        // waits for bytes to sniff HTTP/2, which would ignore the idle timeout.
        let mut conn = std::pin::pin!(builder.serve_connection(io, hyper_service));
        let mut signal_closed = std::pin::pin!(signal_tx.closed().fuse());
        loop {
            tokio::select! {
                result = conn.as_mut() => {
                    if let Err(err) = result {
                        tracing::debug!("connection closed: {err}");
                    }
                    break;
                }
                _ = &mut signal_closed => {
                    conn.as_mut().graceful_shutdown();
                }
            }
        }
    });
}

async fn reject_busy(mut io: TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(1), io.read(&mut buf)).await;
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>";
    let resp = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\nRetry-After: 1\r\n\r\n{xml}",
        xml.len()
    );
    let _ = tokio::time::timeout(Duration::from_secs(1), io.write_all(resp.as_bytes())).await;
}
