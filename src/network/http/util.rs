use arc_swap::ArcSwap;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

pub(crate) static CURRENT_DATE: once_cell::sync::Lazy<Arc<ArcSwap<Arc<str>>>> = once_cell::sync::Lazy::new(|| {
    let now = httpdate::HttpDate::from(std::time::SystemTime::now()).to_string();
    let swap = Arc::new(ArcSwap::from_pointee(Arc::from(now.into_boxed_str())));

    let swap_clone = Arc::clone(&swap);
    may::go!(move || loop {
        let now = std::time::SystemTime::now();
        let subsec = now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_millis();
        let delay = 1_000u64.saturating_sub(subsec as u64);
        may::coroutine::sleep(std::time::Duration::from_millis(delay));

        let new_date = httpdate::HttpDate::from(std::time::SystemTime::now()).to_string();
        swap_clone.store(Arc::<str>::from(new_date.into_boxed_str()).into());
    });

    swap
});

#[cfg(feature = "sys-boring-ssl")]
#[derive(Debug, Copy, Clone)]
pub enum SSLVersion {
    TLS1_2 = 771,    
    TLS1_3,    
}

#[cfg(feature = "sys-boring-ssl")]
pub struct SSL<'a> {
    pub cert_pem: &'a [u8],
    pub chain_pem: Option<&'a [u8]>,
    pub io_timeout: std::time::Duration,
    pub key_pem: &'a [u8],
    pub max_version: SSLVersion,
    pub min_version: SSLVersion,
}

// Map from your enum to boring::ssl::SslVersion
#[cfg(feature = "sys-boring-ssl")]
impl SSLVersion {
    pub fn to_boring(self) -> Option<boring::ssl::SslVersion> {
        match self {
            SSLVersion::TLS1_2 => Some(boring::ssl::SslVersion::TLS1_2),
            SSLVersion::TLS1_3 => Some(boring::ssl::SslVersion::TLS1_3),
        }
    }
}

// RFC 9110-compliant
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    // 1xx Informational
    Continue,
    SwitchingProtocols,
    Processing,
    EarlyHints,

    // 2xx Success
    Ok,
    Created,
    Accepted,
    NonAuthoritativeInformation,
    NoContent,
    ResetContent,
    PartialContent,
    MultiStatus,
    AlreadyReported,
    ImUsed,

    // 3xx Redirection
    MultipleChoices,
    MovedPermanently,
    Found,
    SeeOther,
    NotModified,
    UseProxy,
    TemporaryRedirect,
    PermanentRedirect,

    // 4xx Client Error
    BadRequest,
    Unauthorized,
    PaymentRequired,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    NotAcceptable,
    ProxyAuthenticationRequired,
    RequestTimeout,
    Conflict,
    Gone,
    LengthRequired,
    PreconditionFailed,
    PayloadTooLarge,
    UriTooLong,
    UnsupportedMediaType,
    RangeNotSatisfiable,
    ExpectationFailed,
    ImATeapot,
    MisdirectedRequest,
    UnprocessableEntity,
    Locked,
    FailedDependency,
    TooEarly,
    UpgradeRequired,
    PreconditionRequired,
    TooManyRequests,
    RequestHeaderFieldsTooLarge,
    UnavailableForLegalReasons,

    // 5xx Server Error
    InternalServerError,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
    HttpVersionNotSupported,
    VariantAlsoNegotiates,
    InsufficientStorage,
    LoopDetected,
    NotExtended,
    NetworkAuthenticationRequired,
}

impl Status {
    pub fn as_parts(&self) -> (&'static str, &'static str) {
        use Status::*;
        match self {
            // 1xx
            Continue => ("100", "Continue"),
            SwitchingProtocols => ("101", "Switching Protocols"),
            Processing => ("102", "Processing"),
            EarlyHints => ("103", "Early Hints"),

            // 2xx
            Ok => ("200", "OK"),
            Created => ("201", "Created"),
            Accepted => ("202", "Accepted"),
            NonAuthoritativeInformation => ("203", "Non-Authoritative Information"),
            NoContent => ("204", "No Content"),
            ResetContent => ("205", "Reset Content"),
            PartialContent => ("206", "Partial Content"),
            MultiStatus => ("207", "Multi-Status"),
            AlreadyReported => ("208", "Already Reported"),
            ImUsed => ("226", "IM Used"),

            // 3xx
            MultipleChoices => ("300", "Multiple Choices"),
            MovedPermanently => ("301", "Moved Permanently"),
            Found => ("302", "Found"),
            SeeOther => ("303", "See Other"),
            NotModified => ("304", "Not Modified"),
            UseProxy => ("305", "Use Proxy"),
            TemporaryRedirect => ("307", "Temporary Redirect"),
            PermanentRedirect => ("308", "Permanent Redirect"),

            // 4xx
            BadRequest => ("400", "Bad Request"),
            Unauthorized => ("401", "Unauthorized"),
            PaymentRequired => ("402", "Payment Required"),
            Forbidden => ("403", "Forbidden"),
            NotFound => ("404", "Not Found"),
            MethodNotAllowed => ("405", "Method Not Allowed"),
            NotAcceptable => ("406", "Not Acceptable"),
            ProxyAuthenticationRequired => ("407", "Proxy Authentication Required"),
            RequestTimeout => ("408", "Request Timeout"),
            Conflict => ("409", "Conflict"),
            Gone => ("410", "Gone"),
            LengthRequired => ("411", "Length Required"),
            PreconditionFailed => ("412", "Precondition Failed"),
            PayloadTooLarge => ("413", "Payload Too Large"),
            UriTooLong => ("414", "URI Too Long"),
            UnsupportedMediaType => ("415", "Unsupported Media Type"),
            RangeNotSatisfiable => ("416", "Range Not Satisfiable"),
            ExpectationFailed => ("417", "Expectation Failed"),
            ImATeapot => ("418", "I'm a teapot"),
            MisdirectedRequest => ("421", "Misdirected Request"),
            UnprocessableEntity => ("422", "Unprocessable Entity"),
            Locked => ("423", "Locked"),
            FailedDependency => ("424", "Failed Dependency"),
            TooEarly => ("425", "Too Early"),
            UpgradeRequired => ("426", "Upgrade Required"),
            PreconditionRequired => ("428", "Precondition Required"),
            TooManyRequests => ("429", "Too Many Requests"),
            RequestHeaderFieldsTooLarge => ("431", "Request Header Fields Too Large"),
            UnavailableForLegalReasons => ("451", "Unavailable For Legal Reasons"),

            // 5xx
            InternalServerError => ("500", "Internal Server Error"),
            NotImplemented => ("501", "Not Implemented"),
            BadGateway => ("502", "Bad Gateway"),
            ServiceUnavailable => ("503", "Service Unavailable"),
            GatewayTimeout => ("504", "Gateway Timeout"),
            HttpVersionNotSupported => ("505", "HTTP Version Not Supported"),
            VariantAlsoNegotiates => ("506", "Variant Also Negotiates"),
            InsufficientStorage => ("507", "Insufficient Storage"),
            LoopDetected => ("508", "Loop Detected"),
            NotExtended => ("510", "Not Extended"),
            NetworkAuthenticationRequired => ("511", "Network Authentication Required"),
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (code, msg) = self.as_parts();
        write!(f, "code:{code} msg:{msg}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpHeader {
    Accept,
    AcceptCharset,
    AcceptEncoding,
    AcceptLanguage,
    AcceptRanges,
    AccessControlAllowCredentials,
    AccessControlAllowHeaders,
    AccessControlAllowMethods,
    AccessControlAllowOrigin,
    AccessControlExposeHeaders,
    AccessControlMaxAge,
    AccessControlRequestHeaders,
    AccessControlRequestMethod,
    Age,
    Allow,
    AltSvc,
    Authorization,
    CacheControl,
    CacheStatus,
    CdnCacheControl,
    Connection,
    ContentDisposition,
    ContentEncoding,
    ContentLanguage,
    ContentLength,
    ContentLocation,
    ContentRange,
    ContentSecurityPolicy,
    ContentSecurityPolicyReportOnly,
    ContentType,
    Cookie,
    CrossOriginEmbedderPolicyReportOnly,
    CrossOriginOpenerPolicy,
    Date,
    Dnt,
    Etag,
    Expect,
    Expires,
    Forwarded,
    From,
    Host,
    IfMatch,
    IfModifiedSince,
    IfNoneMatch,
    IfRange,
    IfUnmodifiedSince,
    LastModified,
    Link,
    Location,
    MaxForwards,
    Origin,
    Pragma,
    ProxyAuthenticate,
    ProxyAuthorization,
    PublicKeyPins,
    PublicKeyPinsReportOnly,
    Range,
    Referer,
    ReferrerPolicy,
    Refresh,
    RetryAfter,
    SecWebSocketAccept,
    SecWebSocketExtensions,
    SecWebSocketKey,
    SecWebSocketProtocol,
    SecWebSocketVersion,
    Server,
    SetCookie,
    StrictTransportSecurity,
    Te,
    Trailer,
    TransferEncoding,
    UserAgent,
    Upgrade,
    UpgradeInsecureRequests,
    Vary,
    Via,
    Warning,
    WwwAuthenticate,
    XContentTypeOptions,
    XDnsPrefetchControl,
    XFrameOptions,
    XXssProtection,
}

impl HttpHeader {
    pub fn as_str(&self) -> &'static str
    {
        use HttpHeader::*;
        match self {
            Accept => "accept",
            AcceptCharset => "accept-charset",
            AcceptEncoding => "accept-encoding",
            AcceptLanguage => "accept-language",
            AcceptRanges => "accept-ranges",
            AccessControlAllowCredentials => "access-control-allow-credentials",
            AccessControlAllowHeaders => "access-control-allow-headers",
            AccessControlAllowMethods => "access-control-allow-methods",
            AccessControlAllowOrigin => "access-control-allow-origin",
            AccessControlExposeHeaders => "access-control-expose-headers",
            AccessControlMaxAge => "access-control-max-age",
            AccessControlRequestHeaders => "access-control-request-headers",
            AccessControlRequestMethod => "access-control-request-method",
            Age => "age",
            Allow => "allow",
            AltSvc => "alt-svc",
            Authorization => "authorization",
            CacheControl => "cache-control",
            CacheStatus => "cache-status",
            CdnCacheControl => "cdn-cache-control",
            Connection => "connection",
            ContentDisposition => "content-disposition",
            ContentEncoding => "content-encoding",
            ContentLanguage => "content-language",
            ContentLength => "content-length",
            ContentLocation => "content-location",
            ContentRange => "content-range",
            ContentSecurityPolicy => "content-security-policy",
            ContentSecurityPolicyReportOnly => "content-security-policy-report-only",
            ContentType => "content-type",
            Cookie => "cookie",
            CrossOriginEmbedderPolicyReportOnly => "cross-origin-embedder-policy-report-only",
            CrossOriginOpenerPolicy => "cross-origin-opener-policy",
            Date => "date",
            Dnt => "dnt",
            Etag => "etag",
            Expect => "expect",
            Expires => "expires",
            Forwarded => "forwarded",
            From => "from",
            Host => "host",
            IfMatch => "if-match",
            IfModifiedSince => "if-modified-since",
            IfNoneMatch => "if-none-match",
            IfRange => "if-range",
            IfUnmodifiedSince => "if-unmodified-since",
            LastModified => "last-modified",
            Link => "link",
            Location => "location",
            MaxForwards => "max-forwards",
            Origin => "origin",
            Pragma => "pragma",
            ProxyAuthenticate => "proxy-authenticate",
            ProxyAuthorization => "proxy-authorization",
            PublicKeyPins => "public-key-pins",
            PublicKeyPinsReportOnly => "public-key-pins-report-only",
            Range => "range",
            Referer => "referer",
            ReferrerPolicy => "referrer-policy",
            Refresh => "refresh",
            RetryAfter => "retry-after",
            SecWebSocketAccept => "sec-websocket-accept",
            SecWebSocketExtensions => "sec-websocket-extensions",
            SecWebSocketKey => "sec-websocket-key",
            SecWebSocketProtocol => "sec-websocket-protocol",
            SecWebSocketVersion => "sec-websocket-version",
            Server => "server",
            SetCookie => "set-cookie",
            StrictTransportSecurity => "strict-transport-security",
            Te => "te",
            Trailer => "trailer",
            TransferEncoding => "transfer-encoding",
            UserAgent => "user-agent",
            Upgrade => "upgrade",
            UpgradeInsecureRequests => "upgrade-insecure-requests",
            Vary => "vary",
            Via => "via",
            Warning => "warning",
            WwwAuthenticate => "www-authenticate",
            XContentTypeOptions => "x-content-type-options",
            XDnsPrefetchControl => "x-dns-prefetch-control",
            XFrameOptions => "x-frame-options",
            XXssProtection => "x-xss-protection",
        }
    }
}

impl fmt::Display for HttpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for HttpHeader {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use HttpHeader::*;
        Ok(match s {
            "accept" => Accept,
            "accept-charset" => AcceptCharset,
            "accept-encoding" => AcceptEncoding,
            "accept-language" => AcceptLanguage,
            "accept-ranges" => AcceptRanges,
            "access-control-allow-credentials" => AccessControlAllowCredentials,
            "access-control-allow-headers" => AccessControlAllowHeaders,
            "access-control-allow-methods" => AccessControlAllowMethods,
            "access-control-allow-origin" => AccessControlAllowOrigin,
            "access-control-expose-headers" => AccessControlExposeHeaders,
            "access-control-max-age" => AccessControlMaxAge,
            "access-control-request-headers" => AccessControlRequestHeaders,
            "access-control-request-method" => AccessControlRequestMethod,
            "age" => Age,
            "allow" => Allow,
            "alt-svc" => AltSvc,
            "authorization" => Authorization,
            "cache-control" => CacheControl,
            "cache-status" => CacheStatus,
            "cdn-cache-control" => CdnCacheControl,
            "connection" => Connection,
            "content-disposition" => ContentDisposition,
            "content-encoding" => ContentEncoding,
            "content-language" => ContentLanguage,
            "content-length" => ContentLength,
            "content-location" => ContentLocation,
            "content-range" => ContentRange,
            "content-security-policy-report-only" => ContentSecurityPolicyReportOnly,
            "content-security-policy" => ContentSecurityPolicy,
            "content-type" => ContentType,
            "cookie" => Cookie,
            "cross-origin-embedder-policy-report-only" => CrossOriginEmbedderPolicyReportOnly,
            "cross-origin-opener-policy" => CrossOriginOpenerPolicy,
            "date" => Date,
            "dnt" => Dnt,
            "etag" => Etag,
            "expect" => Expect,
            "expires" => Expires,
            "forwarded" => Forwarded,
            "from" => From,
            "host" => Host,
            "if-match" => IfMatch,
            "if-modified-since" => IfModifiedSince,
            "if-none-match" => IfNoneMatch,
            "if-range" => IfRange,
            "if-unmodified-since" => IfUnmodifiedSince,
            "last-modified" => LastModified,
            "link" => Link,
            "location" => Location,
            "max-forwards" => MaxForwards,
            "origin" => Origin,
            "pragma" => Pragma,
            "proxy-authenticate" => ProxyAuthenticate,
            "proxy-authorization" => ProxyAuthorization,
            "public-key-pins" => PublicKeyPins,
            "public-key-pins-report-only" => PublicKeyPinsReportOnly,
            "range" => Range,
            "referer" => Referer,
            "referrer-policy" => ReferrerPolicy,
            "refresh" => Refresh,
            "retry-after" => RetryAfter,
            "sec-websocket-accept" => SecWebSocketAccept,
            "sec-websocket-extensions" => SecWebSocketExtensions,
            "sec-websocket-key" => SecWebSocketKey,
            "sec-websocket-protocol" => SecWebSocketProtocol,
            "sec-websocket-version" => SecWebSocketVersion,
            "server" => Server,
            "set-cookie" => SetCookie,
            "strict-transport-security" => StrictTransportSecurity,
            "te" => Te,
            "trailer" => Trailer,
            "transfer-encoding" => TransferEncoding,
            "user-agent" => UserAgent,
            "upgrade" => Upgrade,
            "upgrade-insecure-requests" => UpgradeInsecureRequests,
            "vary" => Vary,
            "via" => Via,
            "warning" => Warning,
            "www-authenticate" => WwwAuthenticate,
            "x-content-type-options" => XContentTypeOptions,
            "x-dns-prefetch-control" => XDnsPrefetchControl,
            "x-frame-options" => XFrameOptions,
            "x-xss-protection" => XXssProtection,
            _ => return Err(()),
        })
    }
}