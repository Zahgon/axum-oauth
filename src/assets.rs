//! The `/assets` file server.
//!
//! The source framework's directory service decided several answers before a
//! file was ever read, and those answers are part of the wire contract: any
//! method other than `GET` and `HEAD` is a bodiless `405` listing exactly those
//! two; a path that does not decode to plain, forward-only components (`..`,
//! an encoded `/` smuggling one in, invalid UTF-8) is a bodiless `404` rather
//! than an error page; a directory named without a trailing slash is a bodiless
//! `307` to the same path with the slash added, a directory named with one is
//! looked up as its `index.html` and, there being none, is a bodiless `404`
//! too; a file that cannot be opened is a bodiless `404` only when it is
//! missing, unreadable or below something that is not a directory, and a
//! bodiless `500` for any other file-system error (a name too long, a NUL
//! byte).
//!
//! Once a file is found, only date preconditions are honoured, to the second
//! and as bodiless answers: `If-Unmodified-Since` before `If-Modified-Since`,
//! with entity tags never consulted. A `Range` header is held to the strict
//! grammar the source parsed it with, and only a single range is served; a
//! request for several is refused rather than answered with a multipart body.
//! The target's file service answers each of those differently, so files are
//! served here.

use std::{
    io,
    ops::RangeInclusive,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use http_range_header::RangeUnsatisfiableError;

use actix_web::{
    http::{
        header::{self, HttpDate, IfModifiedSince, IfUnmodifiedSince},
        Method, StatusCode,
    },
    web, HttpMessage, HttpRequest, HttpResponse,
};

const ROOT: &str = "assets";
const PREFIX: &str = "/assets";

pub async fn serve(req: HttpRequest, payload: web::Payload) -> HttpResponse {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return crate::oauth::routes::method_not_allowed(payload, "GET,HEAD").await;
    }

    // The mount point itself is the directory's root, as if requested with its slash.
    let tail = match req.uri().path().strip_prefix(PREFIX) {
        Some("") | None => "/",
        Some(tail) => tail,
    };
    let Some(mut path) = resolve(Path::new(ROOT), tail) else {
        return bare(StatusCode::NOT_FOUND);
    };
    // `tokio::fs` runs the lookups on the blocking pool, off the async worker.
    let is_dir = tokio::fs::metadata(&path)
        .await
        .is_ok_and(|metadata| metadata.is_dir());
    if is_dir {
        if !tail.ends_with('/') {
            return redirect_to_directory(tail, req.uri().query());
        }
        path.push("index.html");
    }

    let contents = match tokio::fs::read(&path).await {
        Ok(contents) => web::Bytes::from(contents),
        Err(err) if is_missing(&err) => return bare(StatusCode::NOT_FOUND),
        Err(_) => return bare(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let last_modified = tokio::fs::metadata(&path)
        .await
        .ok()
        .and_then(|metadata| metadata.modified().ok());

    if let Some(status) = failed_precondition(&req, last_modified) {
        return bare(status);
    }

    let size = contents.len() as u64;
    let mut response = HttpResponse::Ok();
    response
        .insert_header((
            header::CONTENT_TYPE,
            mime_guess::from_path(&path)
                .first_raw()
                .unwrap_or("application/octet-stream"),
        ))
        .insert_header((header::ACCEPT_RANGES, "bytes"));
    if let Some(last_modified) = last_modified {
        response.insert_header((header::LAST_MODIFIED, HttpDate::from(last_modified)));
    }

    let Some(ranges) = requested_ranges(&req, size) else {
        return response.body(contents);
    };
    let unsatisfiable = format!("bytes */{size}");
    match ranges.as_deref() {
        Ok([range]) => response
            .status(StatusCode::PARTIAL_CONTENT)
            .insert_header((
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{size}", range.start(), range.end()),
            ))
            .body(contents.slice(*range.start() as usize..=*range.end() as usize)),
        Ok([]) => response
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .insert_header((header::CONTENT_RANGE, unsatisfiable))
            .body("No range found after parsing range header, please file an issue"),
        Ok(_) => response
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .insert_header((header::CONTENT_RANGE, unsatisfiable))
            .body("Cannot serve multipart range requests"),
        Err(_) => response
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .insert_header((header::CONTENT_RANGE, unsatisfiable))
            .finish(),
    }
}

/// Map the percent-encoded request tail onto a path below `base`, refusing
/// anything that is not a plain component.
fn resolve(base: &Path, tail: &str) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(tail.trim_start_matches('/'))
        .decode_utf8()
        .ok()?;

    let mut path = base.to_path_buf();
    for component in Path::new(&*decoded).components() {
        match component {
            Component::Normal(part) => {
                // A part that is itself more than one component (a drive
                // prefix, say) is refused as well.
                if !Path::new(part)
                    .components()
                    .all(|inner| matches!(inner, Component::Normal(_)))
                {
                    return None;
                }
                path.push(part);
            }
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => return None,
        }
    }

    Some(path)
}

/// The source redirected relative to the mount point, so the location it named
/// lacks the `/assets` prefix; the query string, even an empty one, is kept.
fn redirect_to_directory(tail: &str, query: Option<&str>) -> HttpResponse {
    let location = match query {
        Some(query) => format!("{tail}/?{query}"),
        None => format!("{tail}/"),
    };

    HttpResponse::TemporaryRedirect()
        .insert_header((header::LOCATION, location))
        .finish()
}

/// Whether an error reading a file means there is no file to serve, as opposed
/// to a failure of the file system.
fn is_missing(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied | io::ErrorKind::NotADirectory
    )
}

/// The bodiless answer to a failed date precondition, if one failed.
fn failed_precondition(req: &HttpRequest, last_modified: Option<SystemTime>) -> Option<StatusCode> {
    let modified = last_modified.and_then(whole_seconds)?;

    if let Some(IfUnmodifiedSince(since)) = req.get_header() {
        if whole_seconds(since.into()).is_some_and(|since| modified > since) {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    }
    if let Some(IfModifiedSince(since)) = req.get_header() {
        if whole_seconds(since.into()).is_some_and(|since| modified <= since) {
            return Some(StatusCode::NOT_MODIFIED);
        }
    }

    None
}

/// HTTP dates carry whole seconds, so modification times are compared at that
/// precision.
fn whole_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// The satisfiable byte ranges of a `Range` header, or why there are none.
type Ranges = Result<Vec<RangeInclusive<u64>>, RangeUnsatisfiableError>;

/// The byte ranges a request asks for, if it carries a `Range` header.
fn requested_ranges(req: &HttpRequest, size: u64) -> Option<Ranges> {
    req.headers()
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            http_range_header::parse_range_header(value).and_then(|ranges| ranges.validate(size))
        })
}

fn bare(status: StatusCode) -> HttpResponse {
    HttpResponse::build(status).finish()
}
