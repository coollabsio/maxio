//! Shutdown draining and protective limits.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot, watch};

fn serve_opts(
    max_connections: usize,
    idle: Duration,
    shutdown: Duration,
) -> maxio::serve::ServeOptions {
    maxio::serve::ServeOptions {
        max_header_bytes: 8 * 1024,
        max_connections,
        idle_timeout: idle,
        shutdown_timeout: shutdown,
    }
}

#[tokio::test]
async fn shutdown_drains_the_inflight_request_and_stops_accepting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let started = Arc::new(tokio::sync::Mutex::new(Some(started_tx)));
    let router = Router::new().route(
        "/slow",
        get(move || {
            let started = started.clone();
            async move {
                if let Some(tx) = started.lock().await.take() {
                    let _ = tx.send(());
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
                "done"
            }
        }),
    );
    // Virtual-host rewrite runs before routing. `localhost` is a base domain,
    // so this path-style `/slow` request is not rewritten.
    let app = maxio::server::AppService::new(router, vec!["localhost".to_string()]);
    let (tx, rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        maxio::serve::serve(
            listener,
            app,
            serve_opts(8, Duration::from_secs(30), Duration::from_secs(2)),
            rx,
        )
        .await
        .unwrap()
    });

    let client = tokio::spawn(async move {
        reqwest::get(format!("http://{addr}/slow"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    started_rx.await.unwrap();
    tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "the listener must close once shutdown starts"
    );
    assert_eq!(client.await.unwrap(), "done");
    assert_eq!(
        server.await.unwrap(),
        maxio::serve::ShutdownOutcome::Drained
    );
}

#[tokio::test]
async fn shutdown_aborts_when_the_drain_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let started = Arc::new(tokio::sync::Mutex::new(Some(started_tx)));
    let app = Router::new().route(
        "/slow",
        get(move || {
            let started = started.clone();
            async move {
                if let Some(tx) = started.lock().await.take() {
                    let _ = tx.send(());
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
                "done"
            }
        }),
    );
    let (tx, rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        maxio::serve::serve(
            listener,
            app,
            serve_opts(8, Duration::from_secs(30), Duration::from_millis(200)),
            rx,
        )
        .await
        .unwrap()
    });
    let client = tokio::spawn(async move { reqwest::get(format!("http://{addr}/slow")).await });
    started_rx.await.unwrap();
    tx.send(true).unwrap();
    assert_eq!(
        server.await.unwrap(),
        maxio::serve::ShutdownOutcome::TimedOut
    );
    let _ = client.await;
}

#[tokio::test]
async fn connection_cap_returns_slowdown() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let started = Arc::new(tokio::sync::Mutex::new(Some(started_tx)));
    let app = Router::new().route(
        "/hold",
        get(move || {
            let started = started.clone();
            async move {
                if let Some(tx) = started.lock().await.take() {
                    let _ = tx.send(());
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
                "held"
            }
        }),
    );
    let (_tx, rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        maxio::serve::serve(
            listener,
            app,
            serve_opts(1, Duration::from_secs(30), Duration::from_secs(1)),
            rx,
        )
        .await
        .unwrap()
    });

    let hold = tokio::spawn(async move { reqwest::get(format!("http://{addr}/hold")).await });
    started_rx.await.unwrap();

    let mut extra = tokio::net::TcpStream::connect(addr).await.unwrap();
    extra
        .write_all(b"GET /hold HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), extra.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("503"), "{resp}");
    assert!(resp.contains("SlowDown"), "{resp}");

    hold.abort();
    server.abort();
}

#[tokio::test]
async fn oversized_headers_are_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/fast", get(|| async { "ok" }));
    let (_tx, rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        maxio::serve::serve(
            listener,
            app,
            serve_opts(4, Duration::from_secs(30), Duration::from_secs(1)),
            rx,
        )
        .await
        .unwrap()
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let big = "A".repeat(20_000);
    let req = format!(
        "GET /fast HTTP/1.1\r\nHost: localhost\r\nX-Big: {big}\r\nConnection: close\r\n\r\n"
    );
    let _ = stream.write_all(req.as_bytes()).await;
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("header rejection should respond")
        .unwrap_or(0);
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("431") || resp.contains("400"),
        "expected a header-limit rejection, got {resp:?}"
    );
    server.abort();
}

#[tokio::test]
async fn idle_connection_is_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/fast", get(|| async { "ok" }));
    let (_tx, rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        maxio::serve::serve(
            listener,
            app,
            serve_opts(4, Duration::from_millis(500), Duration::from_secs(1)),
            rx,
        )
        .await
        .unwrap()
    });
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("idle connection should not stay open");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "idle connection should be closed, got {read:?}"
    );
    server.abort();
}

#[tokio::test]
async fn inflight_limit_and_request_timeout() {
    let slots = Arc::new(Semaphore::new(1));
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let started = Arc::new(tokio::sync::Mutex::new(Some(started_tx)));
    let app = Router::new()
        .route(
            "/slow",
            get(move || {
                let started = started.clone();
                async move {
                    if let Some(tx) = started.lock().await.take() {
                        let _ = tx.send(());
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    "ok"
                }
            }),
        )
        .route(
            "/forever",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                "late"
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Duration::from_secs(1),
            maxio::limits::limit_request_time,
        ))
        .layer(axum::middleware::from_fn_with_state(
            slots,
            maxio::limits::limit_inflight,
        ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let slow = tokio::spawn(async move {
        reqwest::get(format!("http://{addr}/slow"))
            .await
            .unwrap()
            .status()
    });
    started_rx.await.unwrap();
    let limited = reqwest::get(format!("http://{addr}/slow")).await.unwrap();
    assert_eq!(limited.status(), 503);
    assert!(limited.text().await.unwrap().contains("SlowDown"));
    assert!(slow.await.unwrap().is_success());

    let timed = reqwest::get(format!("http://{addr}/forever"))
        .await
        .unwrap();
    assert_eq!(timed.status(), 400);
    assert!(timed.text().await.unwrap().contains("RequestTimeout"));
}

#[tokio::test]
async fn finished_connections_do_not_grow_rss() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route("/ok", get(|| async { "ok" }));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let opts = serve_opts(0, Duration::from_millis(50), Duration::from_secs(2));
    tokio::spawn(async move {
        maxio::serve::serve(listener, router, opts, shutdown_rx)
            .await
            .unwrap();
    });

    async fn hit(addr: std::net::SocketAddr) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let _ = stream.read(&mut buf).await;
    }

    for _ in 0..32 {
        hit(addr).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let baseline = vm_rss_kb();
    for _ in 0..4000 {
        hit(addr).await;
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    let after = vm_rss_kb();
    let _ = shutdown_tx.send(true);
    let growth = after.saturating_sub(baseline);
    assert!(
        growth < 6 * 1024,
        "RSS grew {growth} KiB after 4000 short connections (baseline {baseline} KiB, after {after} KiB). Finished connection tasks must be reaped."
    );
}

fn vm_rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kb| kb.parse().ok())
        .unwrap_or(0)
}
