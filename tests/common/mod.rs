use axum::{extract::ConnectInfo, Extension, Router};
use std::net::SocketAddr;

/// Exercise the real routes with a different transport peer address without
/// requiring an OS-specific loopback alias or administrator privileges.
pub struct OtherPeer {
    pub base: String,
    handle: axum_server::Handle,
}

impl OtherPeer {
    pub async fn start(router: Router) -> Self {
        let app = router
            .layer(Extension(ConnectInfo(
                "192.0.2.1:12345".parse::<SocketAddr>().unwrap(),
            )))
            .into_make_service();
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        tokio::spawn(async move {
            axum_server::bind("127.0.0.1:0".parse().unwrap())
                .handle(server_handle)
                .serve(app)
                .await
                .unwrap();
        });
        let addr = handle.listening().await.unwrap();
        Self {
            base: format!("http://{addr}"),
            handle,
        }
    }
}

impl Drop for OtherPeer {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}
