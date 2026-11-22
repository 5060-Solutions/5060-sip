use crate::headers::untyped::*;

#[doc(hidden)]
pub use tokenizer::Tokenizer;

/// Big enum holding in each variant every possible header defined in SIP. All variants hold an
/// [untyped](super::untyped) header which is basically a NewType around String.
///
/// In case a header is not defined in Rsip, parsing will store it in the `Other`
/// variant, which is a tuple of Strings.
/// For instance, constructing the `X-Fs-Sending-Message` header (related to SMS in SIP),
/// you can do:
/// ```
/// let x_fs_sending_message = rsip::Header::Other("X-FS-Sending-Message".into(), "f9c4adc8-9c2a-47d5-a7f1-63d20784685e".into());
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Header {
    Accept(Accept),
    AcceptEncoding(AcceptEncoding),
    AcceptLanguage(AcceptLanguage),
    AlertInfo(AlertInfo),
    Allow(Allow),
    AuthenticationInfo(AuthenticationInfo),
    Authorization(Authorization),
    CSeq(CSeq),
    CallId(CallId),
    CallInfo(CallInfo),
    Contact(Contact),
    ContentDisposition(ContentDisposition),
    ContentEncoding(ContentEncoding),
    ContentLanguage(ContentLanguage),
    ContentLength(ContentLength),
    ContentType(ContentType),
    Date(Date),
    ErrorInfo(ErrorInfo),
    Event(Event),
    Expires(Expires),
    From(From),
    InReplyTo(InReplyTo),
    MaxForwards(MaxForwards),
    MimeVersion(MimeVersion),
    MinExpires(MinExpires),
    Organization(Organization),
    Other(String, String),
    Priority(Priority),
    ProxyAuthenticate(ProxyAuthenticate),
    ProxyAuthorization(ProxyAuthorization),
    ProxyRequire(ProxyRequire),
    RAck(RAck),
    RecordRoute(RecordRoute),
    ReferTo(ReferTo),
    ReplyTo(ReplyTo),
    Require(Require),
    RetryAfter(RetryAfter),
    Route(Route),
    RSeq(RSeq),
    Server(Server),
    Subject(Subject),
    SubscriptionState(SubscriptionState),
    Supported(Supported),
    Timestamp(Timestamp),
    To(To),
    Unsupported(Unsupported),
    UserAgent(UserAgent),
    Via(Via),
    Warning(Warning),
    WwwAuthenticate(WwwAuthenticate),
}

impl std::fmt::Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept(inner) => write!(f, "{}", inner),
            Self::AcceptEncoding(inner) => write!(f, "{}", inner),
            Self::AcceptLanguage(inner) => write!(f, "{}", inner),
            Self::AlertInfo(inner) => write!(f, "{}", inner),
            Self::Allow(inner) => write!(f, "{}", inner),
            Self::AuthenticationInfo(inner) => write!(f, "{}", inner),
            Self::Authorization(inner) => write!(f, "{}", inner),
            Self::CSeq(inner) => write!(f, "{}", inner),
            Self::CallId(inner) => write!(f, "{}", inner),
            Self::CallInfo(inner) => write!(f, "{}", inner),
            Self::Contact(inner) => write!(f, "{}", inner),
            Self::ContentDisposition(inner) => write!(f, "{}", inner),
            Self::ContentEncoding(inner) => write!(f, "{}", inner),
            Self::ContentLanguage(inner) => write!(f, "{}", inner),
            Self::ContentLength(inner) => write!(f, "{}", inner),
            Self::ContentType(inner) => write!(f, "{}", inner),
            Self::Date(inner) => write!(f, "{}", inner),
            Self::ErrorInfo(inner) => write!(f, "{}", inner),
            Self::Event(inner) => write!(f, "{}", inner),
            Self::Expires(inner) => write!(f, "{}", inner),
            Self::From(inner) => write!(f, "{}", inner),
            Self::InReplyTo(inner) => write!(f, "{}", inner),
            Self::MaxForwards(inner) => write!(f, "{}", inner),
            Self::MimeVersion(inner) => write!(f, "{}", inner),
            Self::MinExpires(inner) => write!(f, "{}", inner),
            Self::Organization(inner) => write!(f, "{}", inner),
            Self::Other(key, value) => write!(f, "{}: {}", key, value),
            Self::Priority(inner) => write!(f, "{}", inner),
            Self::ProxyAuthenticate(inner) => write!(f, "{}", inner),
            Self::ProxyAuthorization(inner) => write!(f, "{}", inner),
            Self::ProxyRequire(inner) => write!(f, "{}", inner),
            Self::RAck(inner) => write!(f, "{}", inner),
            Self::RecordRoute(inner) => write!(f, "{}", inner),
            Self::ReferTo(inner) => write!(f, "{}", inner),
            Self::ReplyTo(inner) => write!(f, "{}", inner),
            Self::Require(inner) => write!(f, "{}", inner),
            Self::RetryAfter(inner) => write!(f, "{}", inner),
            Self::Route(inner) => write!(f, "{}", inner),
            Self::RSeq(inner) => write!(f, "{}", inner),
            Self::Server(inner) => write!(f, "{}", inner),
            Self::Subject(inner) => write!(f, "{}", inner),
            Self::SubscriptionState(inner) => write!(f, "{}", inner),
            Self::Supported(inner) => write!(f, "{}", inner),
            Self::Timestamp(inner) => write!(f, "{}", inner),
            Self::To(inner) => write!(f, "{}", inner),
            Self::Unsupported(inner) => write!(f, "{}", inner),
            Self::UserAgent(inner) => write!(f, "{}", inner),
            Self::Via(inner) => write!(f, "{}", inner),
            Self::Warning(inner) => write!(f, "{}", inner),
            Self::WwwAuthenticate(inner) => write!(f, "{}", inner),
        }
    }
}

/// Split a comma-separated header value into individual trimmed values,
/// respecting quoted strings and angle-bracket-enclosed URIs.
fn split_comma_value(value: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut in_angles = 0i32;
    let bytes = value.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '"' if !in_quotes => in_quotes = true,
            '"' if in_quotes => in_quotes = false,
            '<' if !in_quotes => in_angles += 1,
            '>' if !in_quotes && in_angles > 0 => in_angles -= 1,
            ',' if !in_quotes && in_angles == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    results.push(trimmed);
                }
                current.clear();
                i += 1;
                continue;
            }
            _ => {}
        }
        current.push(c);
        i += 1;
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        results.push(trimmed);
    }
    results
}

impl Header {
    /// Returns true if this header type supports comma-separated values per RFC 3261.
    fn supports_comma_separation(&self) -> bool {
        matches!(
            self,
            Header::Via(_)
                | Header::Route(_)
                | Header::RecordRoute(_)
                | Header::Contact(_)
                | Header::Allow(_)
                | Header::Require(_)
                | Header::ProxyRequire(_)
                | Header::Supported(_)
                | Header::Unsupported(_)
                | Header::Accept(_)
                | Header::AcceptEncoding(_)
                | Header::AcceptLanguage(_)
        )
    }

    /// Expand a comma-separated header into multiple individual headers.
    /// Returns a vec of one element if no splitting is needed.
    pub fn split_comma_values(self) -> Vec<Header> {
        if !self.supports_comma_separation() {
            return vec![self];
        }

        // Extract the value string from the header
        let value = match &self {
            Header::Via(h) => h.value().to_string(),
            Header::Route(h) => h.value().to_string(),
            Header::RecordRoute(h) => h.value().to_string(),
            Header::Contact(h) => h.value().to_string(),
            Header::Allow(h) => h.value().to_string(),
            Header::Require(h) => h.value().to_string(),
            Header::ProxyRequire(h) => h.value().to_string(),
            Header::Supported(h) => h.value().to_string(),
            Header::Unsupported(h) => h.value().to_string(),
            Header::Accept(h) => h.value().to_string(),
            Header::AcceptEncoding(h) => h.value().to_string(),
            Header::AcceptLanguage(h) => h.value().to_string(),
            _ => return vec![self],
        };

        let parts = split_comma_value(&value);
        if parts.len() <= 1 {
            return vec![self];
        }

        // Create a new header for each split value
        parts
            .into_iter()
            .map(|v| match &self {
                Header::Via(_) => Header::Via(Via::new(v)),
                Header::Route(_) => Header::Route(Route::new(v)),
                Header::RecordRoute(_) => Header::RecordRoute(RecordRoute::new(v)),
                Header::Contact(_) => Header::Contact(Contact::new(v)),
                Header::Allow(_) => Header::Allow(Allow::new(v)),
                Header::Require(_) => Header::Require(Require::new(v)),
                Header::ProxyRequire(_) => Header::ProxyRequire(ProxyRequire::new(v)),
                Header::Supported(_) => Header::Supported(Supported::new(v)),
                Header::Unsupported(_) => Header::Unsupported(Unsupported::new(v)),
                Header::Accept(_) => Header::Accept(Accept::new(v)),
                Header::AcceptEncoding(_) => Header::AcceptEncoding(AcceptEncoding::new(v)),
                Header::AcceptLanguage(_) => Header::AcceptLanguage(AcceptLanguage::new(v)),
                _ => unreachable!(),
            })
            .collect()
    }
}

#[doc(hidden)]
pub mod tokenizer {
    use super::*;
    use crate::{Error, IResult, TokenizerError};
    use rsip_derives::Utf8Tokenizer;
    use std::convert::TryInto;

    /// Unfold a header value per RFC 3261 S7.3.1: replace CRLF + SP/HT with a single SP.
    fn unfold(value: &str) -> String {
        let mut result = String::with_capacity(value.len());
        let bytes = value.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\r'
                && i + 1 < bytes.len()
                && bytes[i + 1] == b'\n'
                && i + 2 < bytes.len()
                && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t')
            {
                result.push(' ');
                i += 3; // skip CRLF + first whitespace char
                // skip any additional continuation whitespace
                while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                    i += 1;
                }
            } else {
                result.push(bytes[i] as char);
                i += 1;
            }
        }
        result
    }

    /// Return the value string, unfolding if necessary.
    fn header_value(value: &str) -> String {
        if value.contains("\r\n") {
            unfold(value)
        } else {
            value.to_string()
        }
    }

    impl<'a> TryInto<Header> for Tokenizer<'a> {
        type Error = Error;

        fn try_into(self) -> Result<Header, Error> {
            let tokenizer: Utf8Tokenizer = self.try_into()?;
            let value = header_value(tokenizer.value);

            match tokenizer.name {
                s if s.eq_ignore_ascii_case("Accept") => {
                    Ok(Header::Accept(Accept::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Accept-Encoding") => {
                    Ok(Header::AcceptEncoding(AcceptEncoding::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Accept-Language") => {
                    Ok(Header::AcceptLanguage(AcceptLanguage::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Alert-Info") => {
                    Ok(Header::AlertInfo(AlertInfo::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Allow") => {
                    Ok(Header::Allow(Allow::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Authentication-Info") => Ok(
                    Header::AuthenticationInfo(AuthenticationInfo::new(value.clone())),
                ),
                s if s.eq_ignore_ascii_case("Authorization") => {
                    Ok(Header::Authorization(Authorization::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("CSeq") => Ok(Header::CSeq(CSeq::new(value.clone()))),
                s if s.eq_ignore_ascii_case("Call-Id") || s.eq_ignore_ascii_case("Call-ID") || s == "i" => {
                    Ok(Header::CallId(CallId::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Call-Info") => {
                    Ok(Header::CallInfo(CallInfo::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Contact") || s == "m" => {
                    Ok(Header::Contact(Contact::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Content-Disposition") => Ok(
                    Header::ContentDisposition(ContentDisposition::new(value.clone())),
                ),
                s if s.eq_ignore_ascii_case("Content-Encoding") || s == "e" => Ok(Header::ContentEncoding(
                    ContentEncoding::new(value.clone()),
                )),
                s if s.eq_ignore_ascii_case("Content-Language") => Ok(Header::ContentLanguage(
                    ContentLanguage::new(value.clone()),
                )),
                s if s.eq_ignore_ascii_case("Content-Length") || s == "l" => {
                    Ok(Header::ContentLength(ContentLength::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Content-Type") || s == "c" => {
                    Ok(Header::ContentType(ContentType::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Date") => Ok(Header::Date(Date::new(value.clone()))),
                s if s.eq_ignore_ascii_case("Error-Info") => {
                    Ok(Header::ErrorInfo(ErrorInfo::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Event") || s == "o" => {
                    Ok(Header::Event(Event::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Expires") => {
                    Ok(Header::Expires(Expires::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("From") || s == "f" => Ok(Header::From(From::new(value.clone()))),
                s if s.eq_ignore_ascii_case("In-Reply-To") => {
                    Ok(Header::InReplyTo(InReplyTo::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Max-Forwards") => {
                    Ok(Header::MaxForwards(MaxForwards::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Mime-Version") => {
                    Ok(Header::MimeVersion(MimeVersion::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Min-Expires") => {
                    Ok(Header::MinExpires(MinExpires::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Organization") => {
                    Ok(Header::Organization(Organization::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Priority") => {
                    Ok(Header::Priority(Priority::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Proxy-Authenticate") => Ok(Header::ProxyAuthenticate(
                    ProxyAuthenticate::new(value.clone()),
                )),
                s if s.eq_ignore_ascii_case("Proxy-Authorization") => Ok(
                    Header::ProxyAuthorization(ProxyAuthorization::new(value.clone())),
                ),
                s if s.eq_ignore_ascii_case("Proxy-Require") => {
                    Ok(Header::ProxyRequire(ProxyRequire::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("RAck") => {
                    Ok(Header::RAck(RAck::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Record-Route") => {
                    Ok(Header::RecordRoute(RecordRoute::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Refer-To") || s == "r" => {
                    Ok(Header::ReferTo(ReferTo::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Reply-To") => {
                    Ok(Header::ReplyTo(ReplyTo::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Require") => {
                    Ok(Header::Require(Require::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Retry-After") => {
                    Ok(Header::RetryAfter(RetryAfter::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Route") => {
                    Ok(Header::Route(Route::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("RSeq") => {
                    Ok(Header::RSeq(RSeq::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Server") => {
                    Ok(Header::Server(Server::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Subject") || s == "s" => {
                    Ok(Header::Subject(Subject::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Subscription-State") => Ok(
                    Header::SubscriptionState(SubscriptionState::new(value.clone())),
                ),
                s if s.eq_ignore_ascii_case("Supported") || s == "k" => {
                    Ok(Header::Supported(Supported::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Timestamp") => {
                    Ok(Header::Timestamp(Timestamp::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("To") || s == "t" => Ok(Header::To(To::new(value.clone()))),
                s if s.eq_ignore_ascii_case("Unsupported") => {
                    Ok(Header::Unsupported(Unsupported::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("User-Agent") => {
                    Ok(Header::UserAgent(UserAgent::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("Via") || s == "v" => Ok(Header::Via(Via::new(value.clone()))),
                s if s.eq_ignore_ascii_case("Warning") => {
                    Ok(Header::Warning(Warning::new(value.clone())))
                }
                s if s.eq_ignore_ascii_case("WWW-Authenticate") => Ok(Header::WwwAuthenticate(
                    WwwAuthenticate::new(value.clone()),
                )),
                _ => Ok(Header::Other(tokenizer.name.into(), value)),
            }
        }
    }

    #[derive(Debug, PartialEq, Eq, Utf8Tokenizer)]
    pub struct Tokenizer<'a> {
        pub name: &'a [u8],
        pub value: &'a [u8],
    }

    impl<'a> Tokenizer<'a> {
        /// Find the end of a header value, handling RFC 3261 S7.3.1 header folding.
        /// A CRLF followed by SP or HT is a continuation (folded) line.
        /// Returns the length of the value (including any folded CRLFs) and
        /// the total consumed length (value + final CRLF).
        fn find_header_value_end(input: &[u8]) -> Option<(usize, usize)> {
            let mut pos = 0;
            while pos < input.len() {
                if input[pos] == b'\r' && pos + 1 < input.len() && input[pos + 1] == b'\n' {
                    // Check if this CRLF is followed by SP or HT (folding)
                    if pos + 2 < input.len()
                        && (input[pos + 2] == b' ' || input[pos + 2] == b'\t')
                    {
                        // Continuation line — skip past CRLF and keep going
                        pos += 2;
                    } else {
                        // End of header value
                        return Some((pos, pos + 2));
                    }
                } else {
                    pos += 1;
                }
            }
            None
        }

        pub fn tokenize(part: &'a [u8]) -> IResult<'a, Self> {
            use crate::NomError;
            use nom::{
                bytes::complete::{take_while1, tag},
                character::complete::space0,
                combinator::rest,
                sequence::tuple,
            };

            let (after_colon, (name, _, _)) = tuple((
                take_while1(crate::parser_utils::is_token),
                tag(":"),
                space0,
            ))(part)
            .map_err(|_: NomError<'a>| TokenizerError::from(("header", part)).into())?;

            // Try to find end of value with folding support
            if let Some((value_end, consumed)) = Self::find_header_value_end(after_colon) {
                let value = &after_colon[..value_end];
                let rem = &after_colon[consumed..];
                Ok((rem, (name, value).into()))
            } else {
                // No CRLF found — take the rest (last header, no trailing CRLF)
                let (rem, value) = rest(after_colon)
                    .map_err(|_: NomError<'a>| TokenizerError::from(("header", part)).into())?;
                Ok((rem, (name, value).into()))
            }
        }
    }

    impl<'a> std::convert::From<(&'a [u8], &'a [u8])> for Tokenizer<'a> {
        fn from(tuple: (&'a [u8], &'a [u8])) -> Self {
            Self {
                name: tuple.0,
                value: tuple.1,
            }
        }
    }
}
