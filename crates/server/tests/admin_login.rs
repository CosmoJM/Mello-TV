//! The admin page login flow over HTTP, against the real router.

use std::{sync::Arc, time::Duration};

use reqwest::{StatusCode, header};
use serde_json::{Value, json};
use stream_core::{
    error::DomainError,
    ports::MediaEngine,
    providers::{Lookup, Selection},
};
use stream_media::{HttpClient, MediaRelay};
use stream_server::{
    accounts::Accounts,
    app::{self, AppState, AppStateInit},
    auth::Keys,
    config::Config,
    library::Library,
    tmdb::Tmdb,
};
use url::Url;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const API_KEY: &str = "test-api-key-0123456789";

struct NoEngine;

#[async_trait::async_trait]
impl MediaEngine for NoEngine {
    async fn resolve_stream(&self, _: &Lookup) -> Result<Selection, DomainError> {
        Err(DomainError::NotFound("none".into()))
    }
}

async fn server(data: &std::path::Path, library: &std::path::Path) -> Result<String, BoxError> {
    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        data_dir: data.to_path_buf(),
        library_dir: library.to_path_buf(),
        public_url: Url::parse("http://127.0.0.1:1")?,
        public_url_configured: true,
        api_key: None,
        tmdb_api_key: None,
        tmdb_read_token: None,
        proxy: None,
        max_height: 1080,
        audio_languages: Vec::new(),
        sync_interval: Duration::from_secs(3600),
        include_specials: false,
        auto_lists: Vec::new(),
        auto_list_grace: Duration::from_secs(86_400),
        tmdb_lists: Vec::new(),
        jellyfin_url: None,
        jellyfin_api_key: None,
    };
    let keys = Keys::from_api_key(API_KEY.into());
    let tmdb = Tmdb::new(None, None)?;
    let library = Library::open(&config, tmdb.clone(), keys.play_key()).await?;
    let state = AppState::new(AppStateInit {
        keys,
        accounts: Arc::new(Accounts::open(data).await?),
        media: Arc::new(NoEngine),
        relay: Arc::new(MediaRelay::new(HttpClient::new()?)),
        tmdb,
        library,
        public_url: config.public_url.clone(),
        public_url_configured: true,
        max_height: 1080,
        audio_languages: Vec::new(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app::router(state)).await;
    });
    Ok(format!("http://{address}"))
}

fn cookie_of(response: &reqwest::Response) -> Option<String> {
    let set = response.headers().get(header::SET_COOKIE)?.to_str().ok()?;
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Strict"),
        "{set}"
    );
    Some(set.split(';').next()?.to_owned())
}

#[tokio::test]
async fn setup_login_logout_and_csrf_guard() -> Result<(), BoxError> {
    let data = tempfile::tempdir()?;
    let library = tempfile::tempdir()?;
    let base = server(data.path(), library.path()).await?;
    let http = reqwest::Client::new();
    let session = |cookie: Option<&str>| {
        let mut request = http.get(format!("{base}/api/session"));
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        request
    };

    let first: Value = session(None).send().await?.json().await?;
    assert_eq!(first["account_exists"], false);

    // Creating the login needs the API key.
    let wrong = http
        .post(format!("{base}/api/account"))
        .json(&json!({"api_key": "nope", "username": "me", "password": "long enough pw"}))
        .send()
        .await?;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let created = http
        .post(format!("{base}/api/account"))
        .json(&json!({"api_key": API_KEY, "username": "me", "password": "long enough pw"}))
        .send()
        .await?;
    assert_eq!(created.status(), StatusCode::OK);
    let cookie = cookie_of(&created).ok_or("no session cookie")?;

    let now: Value = session(Some(&cookie)).send().await?.json().await?;
    assert_eq!(
        (now["logged_in"].clone(), now["username"].clone()),
        (json!(true), json!("me"))
    );

    // The cookie alone is not enough: requests must come from the page.
    let library_url = format!("{base}/api/library");
    let forged = http
        .get(&library_url)
        .header(header::COOKIE, &cookie)
        .send()
        .await?;
    assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
    let ok = http
        .get(&library_url)
        .header(header::COOKIE, &cookie)
        .header("X-Mello-Request", "1")
        .send()
        .await?;
    assert_eq!(ok.status(), StatusCode::OK);

    // Sign out ends the session.
    http.post(format!("{base}/api/logout"))
        .header(header::COOKIE, &cookie)
        .send()
        .await?;
    let after: Value = session(Some(&cookie)).send().await?.json().await?;
    assert_eq!(after["logged_in"], false);

    // Sign back in with the password.
    let bad = http
        .post(format!("{base}/api/login"))
        .json(&json!({"username": "me", "password": "wrong password"}))
        .send()
        .await?;
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    let good = http
        .post(format!("{base}/api/login"))
        .json(&json!({"username": "me", "password": "long enough pw"}))
        .send()
        .await?;
    assert_eq!(good.status(), StatusCode::OK);
    assert!(cookie_of(&good).is_some());

    // Scripts can still use the API key directly.
    let scripted = http.get(&library_url).bearer_auth(API_KEY).send().await?;
    assert_eq!(scripted.status(), StatusCode::OK);
    Ok(())
}
