use crate::{headers::typed::Tokenize, Error};

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct RAckTokenizer<'a> {
    pub response_num: &'a str,
    pub cseq_num: &'a str,
    pub method: &'a str,
}

impl<'a> Tokenize<'a> for RAckTokenizer<'a> {
    fn tokenize(part: &'a str) -> Result<Self, Error> {
        use nom::{
            bytes::complete::take_until,
            character::complete::space1,
            combinator::rest,
            error::VerboseError,
            sequence::tuple,
        };

        let (_, (response_num, _, cseq_num, _, method)) = tuple((
            take_until::<_, _, VerboseError<&str>>(" "),
            space1,
            take_until(" "),
            space1,
            rest,
        ))(part)
        .map_err(|_| Error::tokenizer(("rack header", part)))?;

        Ok(Self {
            response_num,
            cseq_num,
            method,
        })
    }
}
