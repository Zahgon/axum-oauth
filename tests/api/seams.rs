//! Wire-contract tests for the places where the HTTP layer was rewired.
//!
//! Every case here pins a decision that a plausible alternative wiring would
//! change while still compiling and still leaving the rest of the suite green:
//! the status a rejected body produces, the redirect kind, the `Allow` list,
//! whether `HEAD` reaches the `GET` handler, the media type of a static file,
//! the session and removal cookies, and the shape of each error envelope.
//! They run against a real server for the reason a unit test cannot cover:
//! only the socket shows the bytes the framework actually writes.
use crate::helpers::spawn_app;

fn plain_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn header<'a>(response: &'a reqwest::Response, name: &str) -> Option<&'a str> {
    response.headers().get(name).map(|v| v.to_str().unwrap())
}

#[tokio::test]
async fn static_assets_keep_the_bare_media_type() {
    let app = spawn_app().await;

    let response = plain_client()
        .get(format!("{}/assets/pico.min.css", app.app_address))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    assert_eq!(Some("text/css"), header(&response, "content-type"));
    assert_eq!(None, header(&response, "content-disposition"));
    assert_eq!(None, header(&response, "etag"));
}

#[tokio::test]
async fn form_without_a_content_type_is_unsupported_media_type() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/oauth/signin", app.app_address))
        .body("username=bob&password=secret")
        .send()
        .await
        .unwrap();

    assert_eq!(415, response.status().as_u16());
    assert_eq!(
        Some("text/plain; charset=utf-8"),
        header(&response, "content-type")
    );
    assert_eq!(None, header(&response, "connection"));
    assert_eq!(
        "Form requests must have `Content-Type: application/x-www-form-urlencoded`",
        response.text().await.unwrap()
    );
}

#[tokio::test]
async fn form_with_the_wrong_content_type_is_unsupported_media_type() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/oauth/signin", app.app_address))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(415, response.status().as_u16());
}

#[tokio::test]
async fn undeserializable_form_is_unprocessable_entity() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/oauth/signin", app.app_address))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("username=bob")
        .send()
        .await
        .unwrap();

    assert_eq!(422, response.status().as_u16());
    assert_eq!(
        Some("text/plain; charset=utf-8"),
        header(&response, "content-type")
    );
    assert_eq!(
        "Failed to deserialize form body: missing field `password`",
        response.text().await.unwrap()
    );
}

#[tokio::test]
async fn undeserializable_query_is_bad_request() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/oauth/authorize", app.app_address))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("")
        .send()
        .await
        .unwrap();

    assert_eq!(400, response.status().as_u16());
    assert_eq!(
        "Failed to deserialize query string: missing field `consent`",
        response.text().await.unwrap()
    );
}

#[tokio::test]
async fn a_missing_session_redirects_with_see_other() {
    let app = spawn_app().await;

    let response = plain_client()
        .get(format!(
            "{}/oauth/authorize?response_type=code&client_id=LocalClient",
            app.app_address
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(303, response.status().as_u16());
    assert_eq!(
        Some("/oauth/signin?callback=authorize%3Fresponse_type%3Dcode%26client_id%3DLocalClient"),
        header(&response, "location")
    );
}

#[tokio::test]
async fn signing_in_sets_the_session_cookie_attributes() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/oauth/signin", app.app_address))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("username=bob&password=secret")
        .send()
        .await
        .unwrap();

    assert_eq!(303, response.status().as_u16());
    assert_eq!(Some("/oauth/"), header(&response, "location"));

    let cookie = header(&response, "set-cookie").expect("sign-in sets a session cookie");
    assert!(cookie.starts_with("axum_oauth="), "cookie name: {cookie}");
    assert!(cookie.contains("HttpOnly"), "cookie: {cookie}");
    assert!(cookie.contains("Secure"), "cookie: {cookie}");
    assert!(cookie.contains("SameSite=Lax"), "cookie: {cookie}");
    assert!(cookie.contains("Path=/oauth/"), "cookie: {cookie}");
    assert!(
        cookie.contains("Max-Age=86400") || cookie.contains("Expires="),
        "the session cookie carries a one-day lifetime: {cookie}"
    );
}

#[tokio::test]
async fn a_wrong_password_still_writes_the_session_cookie() {
    let app = spawn_app().await;
    let client = plain_client();

    let unknown = client
        .post(format!("{}/oauth/signin", app.app_address))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("username=nobody&password=secret")
        .send()
        .await
        .unwrap();
    assert_eq!(401, unknown.status().as_u16());
    assert_eq!(
        None,
        header(&unknown, "set-cookie"),
        "an unknown user never reaches the session write"
    );

    let wrong_password = client
        .post(format!("{}/oauth/signin", app.app_address))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("username=bob&password=wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(401, wrong_password.status().as_u16());
    assert!(
        header(&wrong_password, "set-cookie").is_some(),
        "the session is written before the password is checked"
    );
}

#[tokio::test]
async fn signing_out_always_removes_the_session_cookie() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/oauth/signout", app.app_address))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let cookie = header(&response, "set-cookie").expect("sign-out clears the session cookie");
    assert!(cookie.starts_with("axum_oauth="), "cookie: {cookie}");
    assert!(cookie.contains("Max-Age=0"), "cookie: {cookie}");
    assert!(cookie.contains("Path=/oauth/"), "cookie: {cookie}");
    assert!(!cookie.contains("Secure"), "cookie: {cookie}");
    assert!(!cookie.contains("SameSite"), "cookie: {cookie}");
}

#[tokio::test]
async fn a_trailing_slash_is_not_a_route() {
    let app = spawn_app().await;
    let client = plain_client();

    for path in ["/oauth/signout/", "/oauth/signin/", "/api/user/"] {
        let response = client
            .post(format!("{}{path}", app.app_address))
            .send()
            .await
            .unwrap();
        assert_eq!(404, response.status().as_u16(), "path: {path}");
    }
}

#[tokio::test]
async fn a_method_mismatch_lists_the_allowed_methods() {
    let app = spawn_app().await;
    let client = plain_client();

    let response = client
        .delete(format!("{}/oauth/signin", app.app_address))
        .send()
        .await
        .unwrap();
    assert_eq!(405, response.status().as_u16());
    assert_eq!(Some("GET,HEAD,POST"), header(&response, "allow"));

    let response = client
        .get(format!("{}/oauth/signup", app.app_address))
        .send()
        .await
        .unwrap();
    assert_eq!(405, response.status().as_u16());
    assert_eq!(Some("POST"), header(&response, "allow"));
}

#[tokio::test]
async fn head_reaches_the_get_handler() {
    let app = spawn_app().await;

    let response = plain_client()
        .head(format!("{}/oauth/signin", app.app_address))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    assert_eq!(
        Some("text/html; charset=utf-8"),
        header(&response, "content-type")
    );
}

#[tokio::test]
async fn an_unauthenticated_resource_answers_a_plain_text_challenge() {
    let app = spawn_app().await;

    let response = plain_client()
        .get(format!("{}/api/user", app.app_address))
        .send()
        .await
        .unwrap();

    assert_eq!(401, response.status().as_u16());
    assert_eq!(Some("Bearer"), header(&response, "www-authenticate"));
    assert_eq!(
        Some("text/plain; charset=utf-8"),
        header(&response, "content-type")
    );
    assert_eq!("", response.text().await.unwrap());
}

#[tokio::test]
async fn an_unauthenticated_write_outranks_the_body() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/api/user", app.app_address))
        .header("content-type", "application/json")
        .body("{ not json")
        .send()
        .await
        .unwrap();

    assert_eq!(401, response.status().as_u16());
    assert_eq!(Some("Bearer"), header(&response, "www-authenticate"));
    assert_eq!(None, header(&response, "connection"));
}

#[tokio::test]
async fn token_errors_are_json_envelopes() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/oauth/token", app.app_address))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("")
        .send()
        .await
        .unwrap();

    assert_eq!(400, response.status().as_u16());
    assert_eq!(Some("application/json"), header(&response, "content-type"));
    assert_eq!(r#"{"error":"invalid_request"}"#, response.text().await.unwrap());
}

#[tokio::test]
async fn duplicate_authorization_headers_are_an_oauth_error() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/oauth/token", app.app_address))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", "Basic aaa")
        .header("authorization", "Basic bbb")
        .body("grant_type=authorization_code")
        .send()
        .await
        .unwrap();

    assert_eq!(500, response.status().as_u16());
    assert_eq!(
        Some("text/plain; charset=utf-8"),
        header(&response, "content-type")
    );
    assert_eq!(
        "Request has invalid Authorization headers",
        response.text().await.unwrap()
    );
}

#[tokio::test]
async fn a_duplicate_signup_is_a_plain_text_conflict() {
    let app = spawn_app().await;

    let response = plain_client()
        .post(format!("{}/oauth/signup", app.app_address))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("username=bob&password=secret&given_name=Robert")
        .send()
        .await
        .unwrap();

    assert_eq!(409, response.status().as_u16());
    assert_eq!(
        Some("text/plain; charset=utf-8"),
        header(&response, "content-type")
    );
    assert_eq!("User already exists", response.text().await.unwrap());
}
