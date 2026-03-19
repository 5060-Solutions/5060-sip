//! A general purpose library of common SIP types
//!
//! Like [http](https://docs.rs/http/) crate, this crate is a general purpose
//! library for common types found when working
//! with the SIP protocol. You'll find [SipMessage](SipMessage)
//! and its [Request](Request)
//! / [Response](Response)
//! variant types for working as either a client or a server as well
//! as all of their components, like [Method](Method),
//! a very flexible [Uri](Uri),
//! [Version](Version),
//! [StatusCode](StatusCode) etc.
//!
//! Rsip is capable of parsing messages from `bytes`, `&str` or `String` using
//! [nom](https://github.com/Geal/nom) parser and can also generate SIP messages
//! using helpful struct builders.
//!
//! You will notably not find an implementation of sending requests or spinning up
//! a SIP server in this crate. SIP servers, by nature of SIP protocol, are very
//! complex usually and will sit at different crates/libs. Rsip is intended to be
//! the de-facto SIP base library for Rust. It was built to be used inside
//! [viska](https://github.com/vasilakisfil/viska) initially but then was split
//! to a different crate. It was inspired by [libsip](https://github.com/ByteHeathen/libsip)
//! but has taken a bit different path regarding parsing, flexibility & safety.
//!
//! For locating SIP servers ([RFC3263](https://datatracker.ietf.org/doc/html/rfc3263)) take a
//! look on [rsip-dns](https://github.com/vasilakisfil/rsip-dns) library.
//!
//! ## SIP: It's all about headers
//! In case you haven't worked with SIP before let me tell you one thing: headers in SIP play
//! a crucial role, basically most of your logic resides around the headers (and there are plenty
//! of them :) ). `Status` and `Method` of course have their role, but there decisions are more
//! straightforward on what you need to do.
//!
//! Rsip takes a unique role regarding headers mixing together safety and flexibility: by default
//! rsip will parse all headers and convert them to distinct
//! [untyped header](headers::untyped) types,
//! as part of the big fat [Header enum](Header).
//! Each untyped header is basically a NewType around String.
//! This means that, apart from non-UTF8 compliant headers, any header is supported even if your
//! client has a bug or rsip itself has a bug somewhere in a typed header.
//! Also, any parsing on complex headers takes place only when needed, on demand.
//!
//! [Untyped headers](headers::untyped) have their use, but in practice when you want to
//! interact with a header, you need to convert it to its [typed form](headers::typed).
//! Not all headers have a typed form, for instance, some
//! headers are just opaque strings (like [CallID](headers::CallId)), or some headers just need helpful methods
//! instead of a whole new typed struct (like
//! [Expires](headers::Expires), which provides the [seconds](headers::Expires::seconds) method).
//!
//! For instance, creating a new `Call-ID` header can easily be done like (examples taken from
//! [RFC3665](https://datatracker.ietf.org/doc/html/rfc3665)):
//!
//! ```
//! use rsip::headers::UntypedHeader;
//! rsip::headers::CallId::new("1j9FpLxk3uxtm8tn@biloxi.example.com");
//! ```
//!
//! Similarly, generating a `From` header:
//! ```
//! use rsip::headers::{From, UntypedHeader};
//! let from = rsip::headers::From::new("Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl");
//! ```
//!
//! If you want to automatically include all defined traits in Rsip, you can include the prelude:
//! ```
//! use rsip::prelude::*;
//! let from = rsip::headers::From::new("Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl");
//! ```
//!
//! While for `Call-Id`, it's fine to pass in an str (which probably will be generated & saved
//! somewhere else in your application), for many headers working with plain strings doesn't make
//! much sense, like in the `From` header. As mentioned, the main reason untyped headers exist is
//! performance (parsing takes place only when needed) and flexibility (you can throw in there
//! whatever you like ^_^).
//!
//! In order to generate a From header, you will probably need to use its [typed](typed::From) version:
//! ```
//! use rsip::headers::typed::TypedHeader;
//!
//! let typed_from: rsip::typed::From = rsip::typed::From {
//!     display_name: Some("Bob".into()),
//!     uri: rsip::Uri {
//!         scheme: Some(rsip::Scheme::Sips),
//!         auth: Some(rsip::Auth {
//!             user: "Bob".into(),
//!             password: None,
//!         }),
//!         host_with_port: rsip::Domain::from("biloxi.example.com").into(),
//!         ..Default::default()
//!     },
//!     params: vec![rsip::Param::Tag(rsip::param::Tag::new("a73kszlfl"))],
//! };
//! ```
//!
//! ## Uri: a flexible uri struct
//!
//! As you can see in the typed `From` example, a very crucial part is the [Uri](Uri). The uri we want to generate is
//! `sips:bob@biloxi.example.com` as in the untyped header above. Hence:
//! * we specify hat the [scheme](Scheme) of the Uri is `Scheme::Sips`
//! * we specify the auth part of the Uri, but only the user part which is `Bob`. We do that
//! using the helpful [Auth](Auth) struct,
//! * we specify the host part of the Uri, which is defined in the Uri as
//! [HostWithPort](HostWithPort) struct.
//! In our case, it is a simple domain without a port specified.
//! For that we can use the [Domain](Domain) struct that has an automatic convertion to [HostWithPort](HostWithPort)
//! struct. In general you will find a lot of helpful `(Try)From/(Try)Into` convertions to remove
//! boilerplate. According to SIP spec, the URI can hold params (like `method`) and headers,
//! although in practice none really puts those to a SIP URI. That's why we have defaults in there.
//!
//! It is important to note that in order to set the `tag` param, we use the [Tag](param::Tag) struct, found
//! inside the [param](param) module. In the same module you will find various other params that can be
//! used in headers like [From](headers::From), [To](headers::To), [Contact](headers::Contact),
//! [Via](headers::Via) etc.
//!
//! In general, there are tons of helpful `(Try)From/(Try)Into` convertions to remove boilerplate.
//! So when you have a typed header, it's easy to take its untyped form:
//!
//! ```
//! # let typed_from: rsip::typed::From = rsip::typed::From {
//! #     display_name: Some("Bob".into()),
//! #     uri: rsip::Uri {
//! #         scheme: Some(rsip::Scheme::Sips),
//! #         auth: Some(rsip::Auth {
//! #             user: "Bob".into(),
//! #             password: None,
//! #         }),
//! #         host_with_port: rsip::Domain::from("biloxi.example.com").into(),
//! #         ..Default::default()
//! #     },
//! #     params: vec![rsip::Param::Tag(rsip::param::Tag::new("a73kszlfl"))],
//! # };
//! let untyped_from: rsip::headers::From = typed_from.into();
//! ```
//!
//! ## Header: the matching enum
//! [Header](Header) is the enum that holds all variants of the headers. It is there so it's easy to do
//! matches to find relevant headers.
//!
//! Continuing from the previous section, if you want to get the typed or untyped headers as part of
//! the `Header` enum you can do the following:
//! ```
//! # let typed_from: rsip::typed::From = rsip::typed::From {
//! #     display_name: Some("Bob".into()),
//! #     uri: rsip::Uri {
//! #         scheme: Some(rsip::Scheme::Sips),
//! #         auth: Some(rsip::Auth {
//! #             user: "Bob".into(),
//! #             password: None,
//! #         }),
//! #         host_with_port: rsip::Domain::from("biloxi.example.com").into(),
//! #         ..Default::default()
//! #     },
//! #     params: vec![rsip::Param::Tag(rsip::param::Tag::new("a73kszlfl"))],
//! # };
//! let from: rsip::Header = typed_from.into();
//! //or
//! # use rsip::prelude::*;
//! # let untyped_from = rsip::headers::From::new("Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl");
//! let from: rsip::Header = untyped_from.into();
//! ```
//!
//! In case a header is not defined in Rsip, parsing will store it in `Header` enum in the `Other`
//! variant. For instance, constructing the `X-Fs-Sending-Message` header (related to SMS in SIP),
//! you can do:
//! ```
//! let x_fs_sending_message = rsip::Header::Other("X-FS-Sending-Message".into(), "f9c4adc8-9c2a-47d5-a7f1-63d20784685e".into());
//! ```
//! ## Headers: a vec of headers
//! [Headers](Headers) is a newtype around `Vec<Header>`, but it's there to give you better safety along
//! with some helpful methods. In SIP, many headers are allowed to appear more than once time, so
//! if we want to provide something else, maybe we should go with something similar to what the
//! http crate does (a multimap HashMap to take advantage of the characteristics of HTTP headers).
//! But this shouldn't worry you as the external API will remain the same even if the internal
//! implementation is moved from a `Vec<Header>` to a multimap HashMap.
//!
//! In order to push some headers in the [Headers](Headers) you can simple do:
//! ```
//! # use rsip::prelude::*;
//! # let from = rsip::headers::From::new("Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl");
//! # let to = rsip::headers::To::new("Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl");
//! let mut request_headers: rsip::Headers = Default::default();
//! request_headers.push(from.into());
//! request_headers.push(to.into());
//! //.
//! //.
//! //.
//! ```
//!
//! ## The SIP Messages: Request & Response
//! [Request](Request) & [Response](Response) are the main structs that you will use just before you finish creating
//! a SIP message. Creating those are very intuitive as you will only need to "fill-in" their
//! fields. Creating a SIP request while having already a `Headers` vec:
//! ```
//! # let request_headers = Default::default();
//! let request = rsip::Request {
//!     method: rsip::Method::Register,
//!     uri: rsip::Uri {
//!         scheme: Some(rsip::Scheme::Sips),
//!         host_with_port: rsip::Domain::from("ss2.biloxi.example.com").into(),
//!         ..Default::default()
//!     },
//!     headers: request_headers,
//!     version: rsip::Version::V2,
//!     body: vec![],
//! };
//! ```
//!
//! Now you have an [rsip::Request](Request), but sometimes it is helpful to work with the
//! [rsip::SipMessage](SipMessage) enum, especially when you are sitting on the receiver's side.
//! In order to convert a [Request](Request) (or a [Response](Response)) to a
//! [SipMessage](SipMessage) it's simple:
//!
//! ```
//! # let request_headers = Default::default();
//! # let request = rsip::Request {
//! #     method: rsip::Method::Register,
//! #     uri: rsip::Uri {
//! #         scheme: Some(rsip::Scheme::Sips),
//! #         host_with_port: rsip::Domain::from("ss2.biloxi.example.com").into(),
//! #         ..Default::default()
//! #     },
//! #     headers: request_headers,
//! #     version: rsip::Version::V2,
//! #     body: vec![],
//! # };
//! let sip_message: rsip::SipMessage = request.into();
//! //similar
//! # let request_headers = Default::default();
//! # let request = rsip::Request {
//! #     method: rsip::Method::Register,
//! #     uri: rsip::Uri {
//! #         scheme: Some(rsip::Scheme::Sips),
//! #         host_with_port: rsip::Domain::from("ss2.biloxi.example.com").into(),
//! #         ..Default::default()
//! #     },
//! #     headers: request_headers,
//! #     version: rsip::Version::V2,
//! #     body: vec![],
//! # };
//! let sip_message = rsip::SipMessage::Request(request);
//! ```
//!
//! Similarly, creating a response when having already defined the headers in a `response_headers`
//! variable:
//!
//! ```
//! # let response_headers = Default::default();
//! let response = rsip::Response {
//!     status_code: 401.into(),
//!     headers: response_headers,
//!     version: rsip::Version::V2,
//!     body: vec![],
//! };
//!
//! let sip_message: rsip::SipMessage = response.into();
//! ```
//!
//!

pub mod common;
mod error;

pub mod headers;
pub mod message;
pub mod services;

pub use error::{Error, TokenizerError};

pub use headers::{Header, Headers};
pub use message::{Request, Response, SipMessage};

pub use crate::common::uri::*;
pub use crate::common::*;

pub use crate::message::header_macros::*;

pub mod typed {
    pub use crate::headers::typed::*;
}

pub mod prelude {
    pub use crate::{
        headers::{typed::TypedHeader, ToTypedHeader, UntypedHeader},
        message::{HasHeaders, HeadersExt},
    };
}

pub(crate) type NomError<'a> = nom::Err<nom::error::VerboseError<&'a [u8]>>;
pub(crate) type NomStrError<'a> = nom::Err<nom::error::VerboseError<&'a str>>;
pub(crate) type GenericNomError<'a, T> = nom::Err<nom::error::VerboseError<T>>;
pub(crate) type IResult<'a, T> = Result<(&'a [u8], T), nom::Err<TokenizerError>>;
//pub(crate) type SResult<'a, T> = Result<(&'a str, T), nom::Err<TokenizerError>>;
pub(crate) type GResult<I, T> = Result<(I, T), nom::Err<TokenizerError>>;

//need to include &str or &[u8] in definition
pub trait AbstractInput<'a, I>:
    nom::InputTakeAtPosition<Item = I>
    + nom::InputTake
    + Clone
    + Copy
    + nom::FindSubstring<&'a str>
    + nom::Slice<nom::lib::std::ops::RangeFrom<usize>>
    + nom::InputLength
    + nom::InputIter
    + nom::Compare<&'a str>
    + nom::Offset
    + nom::Slice<core::ops::RangeTo<usize>>
    + std::fmt::Debug
    + Into<&'a bstr::BStr>
    + Default
{
    fn is_empty(&self) -> bool;
}

pub trait AbstractInputItem<I>: nom::AsChar + std::cmp::PartialEq<I> + From<u8> + Clone {
    fn is_alphabetic(c: I) -> bool;
    fn is_alphanumeric(c: I) -> bool;
    fn is_token(c: I) -> bool;
}

impl<'a> AbstractInput<'a, char> for &'a str {
    fn is_empty(&self) -> bool {
        <str>::is_empty(self)
    }
}

impl AbstractInputItem<char> for char {
    fn is_alphabetic(c: char) -> bool {
        c.is_ascii_alphabetic()
    }

    fn is_alphanumeric(c: char) -> bool {
        c.is_ascii_alphanumeric()
    }

    fn is_token(c: char) -> bool {
        Self::is_alphanumeric(c) || "-.!%*_+`'~".contains(c)
    }
}

impl<'a> AbstractInput<'a, u8> for &'a [u8] {
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }
}
impl AbstractInputItem<u8> for u8 {
    fn is_alphabetic(c: u8) -> bool {
        nom::character::is_alphabetic(c)
    }

    fn is_alphanumeric(c: u8) -> bool {
        nom::character::is_alphanumeric(c)
    }

    fn is_token(c: u8) -> bool {
        use nom::character::is_alphanumeric;

        is_alphanumeric(c) || "-.!%*_+`'~".contains(char::from(c))
    }
}

pub(crate) mod utils {
    pub fn opt_trim(input: &str) -> Option<&str> {
        let input = input.trim();

        match input.is_empty() {
            true => None,
            false => Some(input),
        }
    }
}

pub(crate) mod parser_utils {
    use crate::TokenizerError;

    pub fn is_token(c: u8) -> bool {
        use nom::character::is_alphanumeric;

        is_alphanumeric(c) || "-.!%*_+`'~".contains(char::from(c))
    }

    pub fn is_empty_or_fail_with<'a, I, T: crate::AbstractInput<'a, I>, S: Into<&'a bstr::BStr>>(
        rem: T,
        tuple: (&'static str, S),
    ) -> Result<(), nom::Err<crate::TokenizerError>> {
        if !rem.is_empty() {
            //TODO: specify that this is trailing input
            //use a comma in params tests to test
            Err(TokenizerError::from(tuple).into())
        } else {
            Ok(())
        }
    }

    /*
    pub fn create_error_for<'a>(rem: &'a [u8], error: &'static str) -> super::NomError<'a> {
        nom::Err::Error(nom::error::VerboseError {
            errors: vec![(rem, nom::error::VerboseErrorKind::Context(error))],
        })
    }
    */

    /*
        pub fn is_unreserved(chr: u8) -> bool {
            use nom::character::is_alphanumeric;

            is_alphanumeric(chr) || "-_.!~*'()".contains(char::from(chr))
        }

        pub fn is_reserved(chr: u8) -> bool {
            ";/?:@&=+$,".contains(char::from(chr))
        }
    */

    /*
        pub fn opt_sc<'a>(
            input: &'a [u8],
        ) -> IResult<&'a [u8], Option<&'a [u8]>, VerboseError<&'a [u8]>> {
            use nom::{bytes::complete::tag, combinator::opt};

            opt(tag(";"))(input)
        }

        pub fn opt_amp<'a>(
            input: &'a [u8],
        ) -> IResult<&'a [u8], Option<&'a [u8]>, VerboseError<&'a [u8]>> {
            use nom::{bytes::complete::tag, combinator::opt};

            opt(tag("&"))(input)
        }
    */
}

// ---------------------------------------------------------------------------
// 5060 Extensions
// ---------------------------------------------------------------------------

/// Parse a SIP fragment (sipfrag) body as used in REFER NOTIFY messages.
///
/// Input: "SIP/2.0 200 OK" or "SIP/2.0 100 Trying"
/// Returns: (status_code, reason_phrase)
pub fn parse_sipfrag(body: &str) -> Option<(u16, String)> {
    let line = body.lines().next()?.trim();
    if !line.starts_with("SIP/2.0 ") {
        return None;
    }
    let rest = &line["SIP/2.0 ".len()..];
    let space = rest.find(' ')?;
    let code: u16 = rest[..space].parse().ok()?;
    let reason = rest[space + 1..].to_string();
    Some((code, reason))
}

/// Parsed Replaces header (RFC 3891).
///
/// Format: `Replaces: call-id;to-tag=X;from-tag=Y`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacesHeader {
    pub call_id: String,
    pub to_tag: Option<String>,
    pub from_tag: Option<String>,
}

impl ReplacesHeader {
    /// Parse a Replaces header value.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let parts: Vec<&str> = value.splitn(2, ';').collect();
        let call_id = parts.first()?.trim().to_string();
        if call_id.is_empty() {
            return None;
        }

        let mut to_tag = None;
        let mut from_tag = None;

        if let Some(params) = parts.get(1) {
            for param in params.split(';') {
                let param = param.trim();
                if let Some(val) = param.strip_prefix("to-tag=") {
                    to_tag = Some(val.to_string());
                } else if let Some(val) = param.strip_prefix("from-tag=") {
                    from_tag = Some(val.to_string());
                }
            }
        }

        Some(Self { call_id, to_tag, from_tag })
    }

    /// Serialize to a header value string.
    pub fn to_header_value(&self) -> String {
        let mut s = self.call_id.clone();
        if let Some(ref t) = self.to_tag {
            s.push_str(&format!(";to-tag={t}"));
        }
        if let Some(ref f) = self.from_tag {
            s.push_str(&format!(";from-tag={f}"));
        }
        s
    }
}

impl std::fmt::Display for ReplacesHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

#[cfg(test)]
mod ext_tests {
    use super::*;

    #[test]
    fn parse_sipfrag_200_ok() {
        let (code, reason) = parse_sipfrag("SIP/2.0 200 OK").unwrap();
        assert_eq!(code, 200);
        assert_eq!(reason, "OK");
    }

    #[test]
    fn parse_sipfrag_100_trying() {
        let (code, reason) = parse_sipfrag("SIP/2.0 100 Trying").unwrap();
        assert_eq!(code, 100);
        assert_eq!(reason, "Trying");
    }

    #[test]
    fn parse_sipfrag_603_decline() {
        let (code, reason) = parse_sipfrag("SIP/2.0 603 Decline\r\n").unwrap();
        assert_eq!(code, 603);
        assert_eq!(reason, "Decline");
    }

    #[test]
    fn parse_sipfrag_invalid() {
        assert!(parse_sipfrag("not a sip fragment").is_none());
        assert!(parse_sipfrag("").is_none());
    }

    #[test]
    fn parse_replaces_full() {
        let r = ReplacesHeader::parse("abc123;to-tag=ttag;from-tag=ftag").unwrap();
        assert_eq!(r.call_id, "abc123");
        assert_eq!(r.to_tag, Some("ttag".to_string()));
        assert_eq!(r.from_tag, Some("ftag".to_string()));
    }

    #[test]
    fn parse_replaces_no_tags() {
        let r = ReplacesHeader::parse("call-id-only").unwrap();
        assert_eq!(r.call_id, "call-id-only");
        assert!(r.to_tag.is_none());
        assert!(r.from_tag.is_none());
    }

    #[test]
    fn parse_replaces_partial_tags() {
        let r = ReplacesHeader::parse("cid;from-tag=ft").unwrap();
        assert_eq!(r.call_id, "cid");
        assert!(r.to_tag.is_none());
        assert_eq!(r.from_tag, Some("ft".to_string()));
    }

    #[test]
    fn replaces_roundtrip() {
        let original = "abc123;to-tag=tt;from-tag=ft";
        let r = ReplacesHeader::parse(original).unwrap();
        assert_eq!(r.to_header_value(), original);
    }

    #[test]
    fn parse_replaces_empty_fails() {
        assert!(ReplacesHeader::parse("").is_none());
        assert!(ReplacesHeader::parse("  ").is_none());
    }

    #[test]
    fn compact_header_via() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"v", value: b"SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::Via(_)));
    }

    #[test]
    fn compact_header_from() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"f", value: b"<sip:alice@example.com>;tag=1234" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::From(_)));
    }

    #[test]
    fn compact_header_to() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"t", value: b"<sip:bob@example.com>" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::To(_)));
    }

    #[test]
    fn compact_header_call_id() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"i", value: b"abc123@host" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::CallId(_)));
    }

    #[test]
    fn compact_header_contact() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"m", value: b"<sip:alice@10.0.0.1>" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::Contact(_)));
    }

    #[test]
    fn compact_header_content_length() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"l", value: b"0" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::ContentLength(_)));
    }

    #[test]
    fn compact_header_content_type() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"c", value: b"application/sdp" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::ContentType(_)));
    }

    #[test]
    fn compact_header_subject() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"s", value: b"Test Subject" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::Subject(_)));
    }

    #[test]
    fn compact_header_supported() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"k", value: b"timer, replaces" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::Supported(_)));
    }

    #[test]
    fn compact_header_event() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"o", value: b"refer" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::Event(_)));
    }

    #[test]
    fn header_folding_unfolds_value() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        use crate::headers::UntypedHeader;
        // A folded Subject header: "hello\r\n world" should become "hello world"
        let tok = Tokenizer { name: b"Subject", value: b"hello\r\n world" };
        let header: Header = tok.try_into().unwrap();
        match header {
            Header::Subject(s) => assert_eq!(s.value(), "hello world"),
            _ => panic!("expected Subject header"),
        }
    }

    #[test]
    fn header_folding_multi_line() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        use crate::headers::UntypedHeader;
        // Multiple folded lines
        let tok = Tokenizer {
            name: b"Subject",
            value: b"line1\r\n line2\r\n\tline3",
        };
        let header: Header = tok.try_into().unwrap();
        match header {
            Header::Subject(s) => assert_eq!(s.value(), "line1 line2 line3"),
            _ => panic!("expected Subject header"),
        }
    }

    #[test]
    fn header_folding_in_full_message() {
        use crate::headers::UntypedHeader;
        let msg = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                   Subject: I know you're there,\r\n \
                            pick up the phone\r\n \
                            and talk to me!\r\n\
                   Content-Length: 0\r\n\r\n";
        let request: Request = msg.try_into().unwrap();
        let subject = request.headers.iter().find_map(|h| match h {
            Header::Subject(s) => Some(s),
            _ => None,
        }).expect("Subject header not found");
        assert_eq!(subject.value(), "I know you're there, pick up the phone and talk to me!");
    }

    #[test]
    fn subscription_state_header_parsed() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"Subscription-State", value: b"active;expires=600" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::SubscriptionState(_)));
    }

    #[test]
    fn comma_separated_via_split_in_message() {
        use crate::headers::UntypedHeader;
        let msg = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776, SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2\r\n\
                   Content-Length: 0\r\n\r\n";
        let request: Request = msg.try_into().unwrap();
        let vias: Vec<_> = request.headers.iter().filter_map(|h| match h {
            Header::Via(v) => Some(v),
            _ => None,
        }).collect();
        assert_eq!(vias.len(), 2);
        assert_eq!(vias[0].value(), "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776");
        assert_eq!(vias[1].value(), "SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2");
    }

    #[test]
    fn comma_separated_route_with_angle_brackets() {
        use crate::headers::UntypedHeader;
        let msg = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                   Route: <sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>\r\n\
                   Content-Length: 0\r\n\r\n";
        let request: Request = msg.try_into().unwrap();
        let routes: Vec<_> = request.headers.iter().filter_map(|h| match h {
            Header::Route(r) => Some(r),
            _ => None,
        }).collect();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].value(), "<sip:proxy1.example.com;lr>");
        assert_eq!(routes[1].value(), "<sip:proxy2.example.com;lr>");
    }

    #[test]
    fn single_value_header_not_split() {
        use crate::headers::UntypedHeader;
        let msg = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776\r\n\
                   Content-Length: 0\r\n\r\n";
        let request: Request = msg.try_into().unwrap();
        let vias: Vec<_> = request.headers.iter().filter_map(|h| match h {
            Header::Via(v) => Some(v),
            _ => None,
        }).collect();
        assert_eq!(vias.len(), 1);
    }

    #[test]
    fn comma_in_non_splittable_header_preserved() {
        use crate::headers::UntypedHeader;
        let msg = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                   Subject: Meeting, tomorrow\r\n\
                   Content-Length: 0\r\n\r\n";
        let request: Request = msg.try_into().unwrap();
        let subject = request.headers.iter().find_map(|h| match h {
            Header::Subject(s) => Some(s),
            _ => None,
        }).expect("Subject header not found");
        assert_eq!(subject.value(), "Meeting, tomorrow");
    }

    #[test]
    fn typed_event_header() {
        use crate::headers::UntypedHeader;
        use crate::headers::ToTypedHeader;
        let event = crate::headers::Event::new("refer;id=1234");
        let typed = event.typed().unwrap();
        assert_eq!(typed.event_type, "refer");
        assert_eq!(typed.id(), Some("1234"));
        assert_eq!(typed.to_string(), "refer;id=1234");
    }

    #[test]
    fn typed_event_simple() {
        use crate::headers::UntypedHeader;
        use crate::headers::ToTypedHeader;
        let event = crate::headers::Event::new("presence");
        let typed = event.typed().unwrap();
        assert_eq!(typed.event_type, "presence");
        assert!(typed.params.is_empty());
    }

    #[test]
    fn typed_subscription_state_active() {
        use crate::headers::UntypedHeader;
        use crate::headers::ToTypedHeader;
        let ss = crate::headers::SubscriptionState::new("active;expires=600");
        let typed = ss.typed().unwrap();
        assert_eq!(typed.state, "active");
        assert_eq!(typed.expires(), Some(600));
        assert_eq!(typed.to_string(), "active;expires=600");
    }

    #[test]
    fn typed_subscription_state_terminated() {
        use crate::headers::UntypedHeader;
        use crate::headers::ToTypedHeader;
        let ss = crate::headers::SubscriptionState::new("terminated;reason=timeout");
        let typed = ss.typed().unwrap();
        assert_eq!(typed.state, "terminated");
        assert_eq!(typed.reason(), Some("timeout"));
    }

    #[test]
    fn typed_subscription_state_pending() {
        use crate::headers::UntypedHeader;
        use crate::headers::ToTypedHeader;
        let ss = crate::headers::SubscriptionState::new("pending;expires=3600;retry-after=120");
        let typed = ss.typed().unwrap();
        assert_eq!(typed.state, "pending");
        assert_eq!(typed.expires(), Some(3600));
        assert_eq!(typed.retry_after(), Some(120));
    }

    #[test]
    fn rack_header_parsed() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"RAck", value: b"776656 1 INVITE" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::RAck(_)));
    }

    #[test]
    fn typed_rack_header() {
        use crate::headers::UntypedHeader;
        use crate::headers::ToTypedHeader;
        let rack = crate::headers::RAck::new("776656 1 INVITE");
        let typed = rack.typed().unwrap();
        assert_eq!(typed.response_num, 776656);
        assert_eq!(typed.cseq_num, 1);
        assert_eq!(typed.method, Method::Invite);
        assert_eq!(typed.to_string(), "776656 1 INVITE");
    }

    #[test]
    fn rack_display_name() {
        use crate::headers::UntypedHeader;
        let rack = crate::headers::RAck::new("776656 1 INVITE");
        assert_eq!(rack.to_string(), "RAck: 776656 1 INVITE");
    }

    #[test]
    fn refer_to_header_parsed() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"Refer-To", value: b"<sip:alice@atlanta.example.com>" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::ReferTo(_)));
    }

    #[test]
    fn refer_to_compact_form() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"r", value: b"<sip:alice@atlanta.example.com>" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::ReferTo(_)));
    }

    #[test]
    fn typed_refer_to_header() {
        use crate::headers::UntypedHeader;
        use crate::headers::ToTypedHeader;
        let rt = crate::headers::ReferTo::new("<sip:alice@atlanta.example.com>");
        let typed = rt.typed().unwrap();
        assert!(typed.display_name.is_none());
        assert_eq!(typed.uri.host_with_port.to_string(), "atlanta.example.com");
    }

    #[test]
    fn typed_refer_to_with_display_name() {
        use crate::headers::UntypedHeader;
        use crate::headers::ToTypedHeader;
        let rt = crate::headers::ReferTo::new("Alice <sip:alice@atlanta.example.com>");
        let typed = rt.typed().unwrap();
        assert_eq!(typed.display_name, Some("Alice".to_string()));
    }

    #[test]
    fn refer_to_display_name_format() {
        use crate::headers::UntypedHeader;
        let rt = crate::headers::ReferTo::new("<sip:alice@atlanta.example.com>");
        assert_eq!(rt.to_string(), "Refer-To: <sip:alice@atlanta.example.com>");
    }

    #[test]
    fn rseq_header_parsed() {
        use std::convert::TryInto;
        use crate::headers::header::Tokenizer;
        let tok = Tokenizer { name: b"RSeq", value: b"776656" };
        let header: Header = tok.try_into().unwrap();
        assert!(matches!(header, Header::RSeq(_)));
    }

    #[test]
    fn rseq_value() {
        use crate::headers::UntypedHeader;
        let rseq = crate::headers::RSeq::new("776656");
        assert_eq!(rseq.seq().unwrap(), 776656);
        assert_eq!(rseq.to_string(), "RSeq: 776656");
    }
}

// ---------------------------------------------------------------------------
// Client-side SIP utilities (migrated from aria-sip-core)
// ---------------------------------------------------------------------------

pub mod sip_auth;
pub mod sip_parser;
pub mod generators;

