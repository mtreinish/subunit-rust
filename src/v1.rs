//! V1 protocol implementation.
//!
//! Note that only an async pull parser for v1 so far (the primary use is
//! scaffolding to support upgrading to v2). For use in sync programs, use
//! `tokio::runtime::Runtime::block_on`. A push parser would need to be
//! developed if that is a requirement.

use core::fmt;
use std::{fmt::Debug, mem};

use async_stream::stream;
use chrono::{DateTime, Utc};
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _};
use tokio_stream::Stream;
use winnow::BStr;

use crate::Error;

/// The default content details for simple bracketed details
pub static TRACEBACK_NAME: &str = "traceback";
pub static X_TRACEBACK: &str = "text/x-traceback;charset=utf-8";

/// An event from a Subunit v1 stream
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// A test started / enumerated
    TestStart(String),
    /// A test succeeded
    TestSuccess(String, Vec<Part>),
    /// A test failed (e.g. assertion failure)
    TestFailure(String, Vec<Part>),
    /// A test errored (e.g. panic, oom etc)
    TestError(String, Vec<Part>),
    /// A test was not actually run
    TestSkip(String, Vec<Part>),
    /// A test failed as expected
    TestExpectedFailure(String, Vec<Part>),
    /// A test expected to fail succeeded
    TestUnexpectedSuccess(String, Vec<Part>),

    /// Push the progress state
    ProgressPush,
    /// Pop the progress state
    ProgressPop,
    /// Set the number of expected tests
    ProgressSet(usize),
    /// Adjust the number of expected tests up or down.
    ///
    /// This is used when a filter discards or adds some tests, preserving the
    /// expectation that the number of TestStart's observed will match the
    /// number of expected tests.
    ProgressCurrent(isize),

    /// Content that could not be parsed, but was valid utf8
    Text(String),
    /// Binary unparsable content
    Bytes(Vec<u8>),

    /// Tags command: added tags in .0 and removed in .1
    Tags(Vec<String>, Vec<String>),
    /// What is the time that the next event 'happens' at.
    Time(DateTime<Utc>),
    EndOfStream,
}

impl Event {
    /// Create a Text or Bytes from a buffer
    pub fn from_buffer(buf: &[u8]) -> Self {
        let buf = buf.to_vec();
        String::from_utf8(buf)
            .map(|s| Event::Text(s))
            .unwrap_or_else(|e| Event::Bytes(e.into_bytes()))
    }
}

/// A single chunk of a test status file
#[derive(Clone, PartialEq)]
pub struct Part {
    /// The content type of the part
    pub content_type: String,
    /// The name of the part
    pub name: String,
    /// The content of the part
    pub bytes: Vec<u8>,
}

impl Part {
    /// Create a new Part
    pub fn new(content_type: &str, name: &str, bytes: &[u8]) -> Self {
        Self {
            content_type: content_type.to_string(),
            name: name.to_string(),
            bytes: bytes.to_vec(),
        }
    }
}

impl Debug for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Part")
            .field("content_type", &self.content_type)
            .field("name", &self.name)
            .field("bytes", &BStr::new(&self.bytes))
            .finish()
    }
}

/// An event associated with a test
#[derive(Clone, Debug, PartialEq)]
pub struct TestEvent;

/// An event not associated with a test
#[derive(Clone, Debug, PartialEq)]
pub struct GlobalEvent;

/// Construct a parser on an AsyncReadBuf + Debug
///
/// Differences from the Python version:
///
/// - rather than generating various TestProtocol calls, this iterates over Events
/// - bracket escaping is not implemented
/// - all the attachments for one test are buffered in memory
/// - progress events are not processes within brackets
pub fn parse(
    reader: &mut dyn SubunitStream,
) -> impl Stream<Item = Result<Event, crate::Error>> + '_ {
    TestProtocolServer {
        reader,
        state: ParseState::Global,
    }
    .stream()
}

/// Defines the traits needed for a parser stream.
pub trait SubunitStream: AsyncBufRead + Unpin + fmt::Debug {}

impl<T> SubunitStream for T where T: AsyncBufRead + Unpin + fmt::Debug {}

mod parser {
    //! Wire -> tokens parser for the subunit v1 protocol.

    use std::str::from_utf8;

    use chrono::NaiveDateTime;
    use winnow::{
        ascii::line_ending,
        combinator::{alt, cut_err, fail, preceded, repeat_till, terminated, trace},
        error::{
            ContextError, ErrMode, ErrorKind, FromExternalError, ParserError, StrContext,
            StrContextValue,
        },
        token::{take, take_till, take_until, take_while},
        BStr, PResult, Parser, Partial, Stateful,
    };

    use super::{Event, Part, TRACEBACK_NAME, X_TRACEBACK};

    #[derive(Debug)]
    pub(crate) struct State<'s>(pub &'s Option<&'s str>);

    pub(crate) type Stream<'s> = Stateful<Partial<&'s BStr>, State<'s>>;

    pub fn parse_cmd_start<'s>(input: &mut Stream<'s>) -> PResult<&'s [u8]> {
        alt(("test ", "test: ", "testing ", "testing: ")).parse_next(input)
    }

    fn parse_cmd_success<'s>(input: &mut Stream<'s>) -> PResult<&'s [u8]> {
        alt(("success ", "success: ")).parse_next(input)
    }

    fn parse_cmd_failure<'s>(input: &mut Stream<'s>) -> PResult<&'s [u8]> {
        alt(("failure ", "failure: ")).parse_next(input)
    }

    fn parse_cmd_error<'s>(input: &mut Stream<'s>) -> PResult<&'s [u8]> {
        alt(("error ", "error: ")).parse_next(input)
    }

    fn parse_cmd_skip<'s>(input: &mut Stream<'s>) -> PResult<&'s [u8]> {
        alt(("skip ", "skip: ")).parse_next(input)
    }

    fn parse_cmd_xfail<'s>(input: &mut Stream<'s>) -> PResult<&'s [u8]> {
        alt(("xfail ", "xfail: ")).parse_next(input)
    }

    fn parse_cmd_uxsuccess<'s>(input: &mut Stream<'s>) -> PResult<&'s [u8]> {
        alt(("uxsuccess ", "uxsuccess: ")).parse_next(input)
    }

    enum DetailStyle {
        Bracketed,
        MultiPart,
    }

    fn parse_label_and_detail_style<'s>(
        input: &mut Stream<'s>,
        line: &'s [u8],
    ) -> PResult<(&'s str, Option<DetailStyle>)> {
        let line = from_utf8(line)
            .map_err(|e| ErrMode::from_external_error(input, ErrorKind::Verify, e))?;

        let (name, detail_style) = if line.ends_with(" [") {
            let line = &line[..line.len() - 2]; // Safe from the ends_with check
            (line, Some(DetailStyle::Bracketed))
        } else if line.ends_with(" [ multipart") {
            let line = &line[..line.len() - 12]; // Safe from the ends_with check
            (line, Some(DetailStyle::MultiPart))
        } else {
            (line, None)
        };
        if name.is_empty() {
            return Err(ErrMode::from_error_kind(input, ErrorKind::Fail));
        }

        Ok((name, detail_style))
    }

    /// Parse a test label and optional details into basic types
    fn parse_label_details<'s>(input: &mut Stream<'s>) -> PResult<(String, Vec<Part>)> {
        let line = trace(
            "label",
            terminated(take_till(1.., |c| c == b'\r' || c == b'\n'), line_ending),
        )
        .parse_next(input)?;

        let (label, detail_style) = parse_label_and_detail_style(input, line)?;
        check_name_match(input, &label)?;
        match detail_style {
            Some(DetailStyle::Bracketed) => alt((
                (&b"]"[..], line_ending).value((label, &[][..])),
                (
                    (take_until(0.., &b"\n]\n"[..]), line_ending).take(),
                    b"]",
                    line_ending,
                )
                    .map(|(y, _, _): (&[u8], _, _)| (label, y)),
            ))
            .context(StrContext::Label("test label"))
            .context(StrContext::Expected(StrContextValue::Description(
                "utf8 string",
            )))
            .map(|(name, details)| {
                (
                    name.to_string(),
                    vec![Part::new(X_TRACEBACK, TRACEBACK_NAME, details)],
                )
            })
            .parse_next(input),
            Some(DetailStyle::MultiPart) => repeat_till(0.., parse_part, &b"]\n"[..])
                .map(|(parts, _acc): (Vec<Part>, _)| (label.to_string(), parts))
                .parse_next(input),
            None => return Ok((label.to_string(), vec![])),
        }
    }

    fn check_name_match<'s>(
        input: &mut Stateful<Partial<&BStr>, State<'s>>,
        name: &'_ str,
    ) -> PResult<()> {
        if &Some(name) == input.state.0 {
            Ok(())
        } else {
            Err(ErrMode::Cut(ContextError::new()))
        }
    }

    /// parse a single length prefixed chunk of a multi-part part
    fn parse_chunk<'s>(input: &mut Stream<'s>) -> PResult<&'s [u8]> {
        let len = terminated(take_until(0.., &b"\r\n"[..]), &b"\r\n"[..])
            .parse_to::<usize>()
            .parse_next(input)?;
        let bytes = take(len).parse_next(input)?;
        Ok(bytes)
    }

    /// parse all the bytes of a multi-part part.
    /// We could consider emitting each length-prefixed chunk to reduce memory pressure, if
    fn parse_part<'s>(input: &mut Stream<'s>) -> PResult<super::Part> {
        let (content_type, name) = (
            (b"Content-Type: ", take_until(0.., &b"\n"[..]), line_ending)
                .map(|(_, content_type, _)| content_type),
            terminated(take_until(0.., &b"\n"[..]), &b"\n"[..]),
        )
            .try_map(|(content_type, name)| {
                from_utf8(content_type)
                    .and_then(|content_type| from_utf8(name).map(|name| (content_type, name)))
            })
            .parse_next(input)?;
        let bytes: Vec<&[u8]> = repeat_till(0.., parse_chunk, &b"0\r\n"[..])
            .map(|(acc, _term)| acc)
            .parse_next(input)?;
        let bytes = bytes.join(&[][..]);
        Ok(super::Part {
            content_type: content_type.to_string(),
            name: name.to_string(),
            bytes,
        })
    }

    /// Parse a tags command.
    fn parse_tags<'s>(input: &mut Stream<'s>) -> PResult<Event> {
        let tags = preceded(
            "tags: ",
            terminated(take_till(0.., |c| b"\r\n".contains(&c)), line_ending),
        )
        .try_map(|tags| from_utf8(tags))
        .parse_next(input)?;

        let mut added = vec![];
        let mut removed = vec![];
        for tag in tags.split_whitespace() {
            if tag.starts_with('-') {
                removed.push(tag[1..].to_string());
            } else {
                added.push(tag.to_string());
            }
        }
        Ok(Event::Tags(added, removed))
    }

    /// Parse a time command.
    /// time: YYYY-MM-DD HH:MM:SSZ
    fn parse_time<'s>(input: &mut Stream<'s>) -> PResult<Event> {
        preceded(
            "time: ",
            terminated(take_till(0.., |c| b"\r\n".contains(&c)), line_ending),
        )
        .try_map(|time| from_utf8(time))
        // Strictly this is too broad, but can't see a way to emulate Z support on chrono otherwise.
        .try_map(|time| NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%SZ"))
        .map(|time| Event::Time(time.and_utc()))
        .parse_next(input)
    }

    /// Main entry point for parsing when in a test context
    pub fn parse_subunit_event_in_test<'s>(input: &mut Stream<'s>) -> PResult<Event> {
        // a closure-factory to make this less repetitive might be nice.
        alt((
            preceded(parse_cmd_success, cut_err(parse_label_details))
                .map(|(name, details)| Event::TestSuccess(name, details)),
            preceded(parse_cmd_failure, cut_err(parse_label_details))
                .map(|(name, details)| Event::TestFailure(name, details)),
            preceded(parse_cmd_error, cut_err(parse_label_details))
                .map(|(name, details)| Event::TestError(name, details)),
            preceded(parse_cmd_skip, cut_err(parse_label_details))
                .map(|(name, details)| Event::TestSkip(name, details)),
            preceded(parse_cmd_xfail, cut_err(parse_label_details))
                .map(|(name, details)| Event::TestExpectedFailure(name, details)),
            preceded(parse_cmd_uxsuccess, cut_err(parse_label_details))
                .map(|(name, details)| Event::TestUnexpectedSuccess(name, details)),
            parse_tags,
            parse_time,
            fail.context(StrContext::Label("command"))
                .context(StrContext::Expected(StrContextValue::Description(
                    "test, success, failure, error, skip, or xfail, followed by optional details",
                ))),
        ))
        .parse_next(input)
    }

    fn parse_test<'s>(input: &mut Stream<'s>) -> PResult<Event> {
        terminated(
            (
                parse_cmd_start,
                cut_err(take_till(0.., |c| c == b'\r' || c == b'\n'))
                    .context(StrContext::Label("test label"))
                    .context(StrContext::Expected(StrContextValue::Description(
                        "utf8 string",
                    ))),
            ),
            line_ending,
        )
        .try_map(|(_x, y)| from_utf8(y).map(|s| Event::TestStart(s.to_string())))
        .parse_next(input)
    }

    fn parse_usize<'s>(input: &mut Stream<'s>) -> PResult<usize> {
        take_while(1.., ((b'0'..=b'9'),))
            .parse_to()
            .parse_next(input)
    }

    fn parse_isize<'s>(input: &mut Stream<'s>) -> PResult<isize> {
        take_while(1.., ((b'0'..=b'9'),))
            .parse_to()
            .parse_next(input)
    }

    /// Main entry point for parsing when in a global context
    pub fn parse_subunit_event_global<'s>(input: &mut Stream<'s>) -> PResult<Event> {
        alt((
            parse_test,
            terminated(&b"progress: push"[..], line_ending).value(Event::ProgressPush),
            terminated(&b"progress: pop"[..], line_ending).value(Event::ProgressPop),
            terminated(preceded(&b"progress: +"[..], parse_isize), line_ending)
                .map(Event::ProgressCurrent),
            terminated(preceded(&b"progress: -"[..], parse_isize), line_ending)
                .map(|v| Event::ProgressCurrent(-v)),
            terminated(preceded(&b"progress: "[..], parse_usize), line_ending)
                .map(Event::ProgressSet),
            terminated(&b"progress: push"[..], line_ending).value(Event::ProgressPush),
            parse_tags,
            parse_time,
            fail.context(StrContext::Label("command"))
                .context(StrContext::Expected(StrContextValue::StringLiteral(
                    "test ",
                ))),
        ))
        .parse_next(input)
    }

    #[cfg(test)]
    mod tests {

        use winnow::{
            error::{ErrMode, ErrorKind, Needed, ParserError},
            BStr, Partial,
        };

        use crate::v1::{Part, TRACEBACK_NAME, X_TRACEBACK};

        #[test]
        fn test_parse_test_start() {
            let mut input = BStr::new(&b"test "[..]);
            let state = None;
            let mut input = super::Stream {
                input: Partial::new(&mut input),
                state: super::State(&state),
            };
            let output = super::parse_cmd_start(&mut input);
            assert_eq!(Ok(&b"test "[..]), output);
        }

        #[test]
        fn test_parse_test_success() {
            let mut input = BStr::new(&b"success "[..]);
            let mut state = None;
            let mut input = super::Stream {
                input: Partial::new(&mut input),
                state: super::State(&mut state),
            };
            let output = super::parse_cmd_success(&mut input).unwrap();
            assert_eq!(&b"success "[..], output);
        }

        #[test]
        fn test_label_details_partial() {
            let mut input = BStr::new(&b"label"[..]);
            let mut state = None;
            let mut input = super::Stream {
                input: Partial::new(&mut input),
                state: super::State(&mut state),
            };
            let output = super::parse_label_details(&mut input).unwrap_err();
            assert_eq!(ErrMode::Incomplete(Needed::new(1)), output);
        }

        #[test]
        fn test_label_details_simple() {
            let mut input = BStr::new(&b"label\n"[..]);
            let mut state = Some("label");
            let mut input = super::Stream {
                input: Partial::new(&mut input),
                state: super::State(&mut state),
            };
            let output = super::parse_label_details(&mut input).unwrap();
            assert_eq!(("label".into(), vec![]), output);
        }

        fn stream<'s>(input: &'s [u8], state: &'s mut Option<&'s str>) -> super::Stream<'s> {
            let mut input = BStr::new(input);
            super::Stream {
                input: Partial::new(&mut input),
                state: super::State(state),
            }
        }

        #[test]
        fn test_label_details_wrong_name() {
            let input = &b"failure: test_name [\n"[..];
            let mut state = Some("other_name");
            let mut input = stream(&input, &mut state);
            // parses as an error, which the line based iterator will catch
            let err = super::parse_label_details(&mut input).unwrap_err();
            assert_eq!(ErrMode::from_error_kind(&input, ErrorKind::Fail).cut(), err);
        }

        #[test]
        fn test_label_details_bracketed() {
            let input = &b"label [\nfoo\n]\n"[..];
            let mut state = Some("label");
            let mut input = stream(&input, &mut state);
            let output = super::parse_label_details(&mut input).unwrap();
            assert_eq!(
                (
                    "label".into(),
                    vec![Part::new(X_TRACEBACK, TRACEBACK_NAME, "foo\n".as_bytes()),]
                ),
                output
            );
        }

        #[test]
        fn test_label_details_bracketed_multipart() {
            let input = &b"label [ multipart\nContent-Type: type/sub-type;p=v\nexample1\n2\r\n122\r\n340\r\nContent-Type: type/sub-type;p=v\nexample2\n2\r\n432\r\n210\r\n]\n"[..];
            let mut state = Some("label");
            let mut input = stream(&input, &mut state);
            let output = super::parse_label_details(&mut input).unwrap();
            assert_eq!(
                (
                    "label".into(),
                    vec![
                        Part::new("type/sub-type;p=v", "example1", "1234".as_bytes()),
                        Part::new("type/sub-type;p=v", "example2", "4321".as_bytes())
                    ]
                ),
                output
            );
        }

        #[test]
        fn test_part_smoke() {
            let input = &b"Content-Type: type/sub-type;p=v\nexample\n2\r\n122\r\n340\r\n"[..];
            let mut state = Some("label");
            let mut input = stream(&input, &mut state);
            let output = super::parse_part(&mut input).unwrap();
            assert_eq!(
                Part::new("type/sub-type;p=v", "example", &b"1234"[..]),
                output
            );
        }

        #[test]
        fn test_chunk() {
            let input = &b"10\r\n1234567890"[..];
            let mut state = Some("label");
            let mut input = stream(&input, &mut state);
            let output = super::parse_chunk(&mut input).unwrap();
            assert_eq!(&b"1234567890"[..], output);
        }
    }
}

enum ParseState {
    InTest(String),
    Global,
}

/// Parses subunit v1 by reading from an AsyncBufRead.
pub struct TestProtocolServer<'a> {
    reader: &'a mut dyn SubunitStream,
    state: ParseState,
}

impl<'a> TestProtocolServer<'a> {
    async fn next(&mut self) -> Result<Event, crate::Error> {
        eprintln!("next");
        let mut buf = vec![];
        // parse the command using winnow
        loop {
            use winnow::Partial;
            use winnow::{error::ErrMode, BStr, Parser};

            let len = self.reader.read_until(b'\n', &mut buf).await?;
            if buf.is_empty() {
                return self.generate_end_of_stream();
            }

            eprintln!("Parsing:");
            let mut input = dbg!(BStr::new(&buf));

            match &self.state {
                ParseState::InTest(test_name) => {
                    let test_name = Some(test_name.as_str());
                    let mut input = parser::Stream {
                        input: Partial::new(&mut input),
                        state: parser::State(&test_name),
                    };
                    let parsed = parser::parse_subunit_event_in_test.parse_next(&mut input);
                    match parsed {
                        Err(ErrMode::Incomplete(_n)) => {
                            if len == 0 {
                                // end of stream when more data was needed
                                return self.generate_end_of_stream();
                            }
                            continue;
                        }
                        Err(_e) => {
                            // permanent error: provide the buffered lines as Text
                            return Ok(Event::from_buffer(&buf));
                        }

                        Ok(event) => {
                            match event {
                                // end of test events
                                Event::TestSuccess(_, _)
                                | Event::TestFailure(_, _)
                                | Event::TestError(_, _)
                                | Event::TestSkip(_, _)
                                | Event::TestExpectedFailure(_, _)
                                | Event::TestUnexpectedSuccess(_, _) => {
                                    self.state = ParseState::Global;
                                    return Ok(event);
                                }

                                _ => {
                                    return Ok(event);
                                }
                            }
                        }
                    }
                }
                ParseState::Global => {
                    let test_name = None;
                    let mut input = parser::Stream {
                        input: Partial::new(&mut input),
                        state: parser::State(&test_name),
                    };
                    if let Ok(event) = parser::parse_subunit_event_global.parse_next(&mut input) {
                        match &event {
                            Event::TestStart(test_name) => {
                                self.state = ParseState::InTest(test_name.clone());
                                return Ok(event);
                            }

                            _ => {
                                return Ok(event);
                            }
                        }
                    }
                }
            }
            // Not recognized as a subunit event in the current state
            return Self::maybe_utf8(buf);
        }
    }

    fn generate_end_of_stream(&mut self) -> Result<Event, Error> {
        let old_state = mem::replace(&mut self.state, ParseState::Global);
        if let ParseState::InTest(test_name) = old_state {
            let message = format!("lost connection during test '{test_name}'");
            return Ok(Event::TestError(
                test_name,
                vec![Part::new(X_TRACEBACK, TRACEBACK_NAME, message.as_bytes())],
            ));
        }
        return Ok(Event::EndOfStream);
    }

    /// Read from the stream.
    pub fn stream(mut self) -> impl Stream<Item = Result<Event, crate::Error>> + 'a {
        stream! {
            loop {
                let next = self.next().await;
                if matches!(next, Ok(Event::EndOfStream)) {
                    break;
                }
                yield next;
            }
        }
    }

    fn maybe_utf8(buf: Vec<u8>) -> Result<Event, crate::Error> {
        String::from_utf8(buf)
            .map(|s| Event::Text(s))
            .or_else(|e| Ok(Event::Bytes(e.into_bytes())))
    }
}

impl std::fmt::Debug for TestProtocolServer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestProtocolServer").finish()
    }
}

#[cfg(test)]
mod tests {

    use chrono::NaiveDate;
    use tokio::io::AsyncReadExt;
    use tokio_stream::StreamExt;

    use crate::v1::{Event, Part, TRACEBACK_NAME, X_TRACEBACK};

    async fn parse_stream(mut stream: &[u8]) -> Vec<super::Event> {
        let stream: &mut dyn super::SubunitStream = &mut stream;
        let parser = super::parse(stream);
        let events = parser
            .collect::<Result<Vec<_>, crate::Error>>()
            .await
            .unwrap();
        let mut buf = vec![];
        assert_eq!(0, stream.read_to_end(&mut buf).await.unwrap());
        events
    }

    #[tokio::test]
    async fn test_story() {
        let stream = &b"test old mcdonald\nsuccess old mcdonald\n"[..];
        let events = parse_stream(stream).await;
        assert_eq!(
            &[
                Event::TestStart("old mcdonald".into()),
                Event::TestSuccess("old mcdonald".into(), vec![])
            ],
            &events[..]
        );
    }

    #[tokio::test]
    async fn test_command_in_wrong_state() {
        let stream = &b"success old mcdonald\n"[..];
        let events = parse_stream(stream).await;
        assert_eq!(&[Event::Text("success old mcdonald\n".into())], &events[..]);
    }

    #[tokio::test]
    async fn test_story_two() {
        let err_msg = "foo.c:53:ERROR invalid state\n";
        let stream = [
            &b"test old mcdonald\n"[..],
            b"success old mcdonald\n",
            b"test bing crosby\n",
            b"failure bing crosby [\n",
            err_msg.as_bytes(),
            b"]\n",
            b"test an error\n",
            b"error an error\n",
        ];

        let events = parse_stream(&stream.join(&[][..])[..]).await;
        assert_eq!(
            &[
                Event::TestStart("old mcdonald".into()),
                Event::TestSuccess("old mcdonald".into(), vec![]),
                Event::TestStart("bing crosby".into()),
                Event::TestFailure(
                    "bing crosby".into(),
                    vec![Part::new(X_TRACEBACK, TRACEBACK_NAME, err_msg.as_bytes())]
                ),
                Event::TestStart("an error".into()),
                Event::TestError("an error".into(), vec![])
            ],
            &events[..]
        );
    }

    #[tokio::test]
    async fn test_start_test_variants() {
        for cmd in &["test", "test:", "testing", "testing:"] {
            let stream = format!("{cmd} old mcdonald\nsuccess old mcdonald\n");
            let stream = stream.as_bytes();
            let events = parse_stream(&stream).await;
            assert_eq!(
                &[
                    Event::TestStart("old mcdonald".into()),
                    Event::TestSuccess("old mcdonald".into(), vec![])
                ],
                &events[..]
            );
        }
    }

    #[tokio::test]
    async fn test_indented_test_colon_ignored() {
        let stream = &b" test: old mcdonald\n"[..];
        let events = parse_stream(&stream).await;
        assert_eq!(&[Event::Text(" test: old mcdonald\n".into()),], &events[..]);
    }

    fn end_keywords() -> (Vec<&'static [u8]>, Vec<Event>) {
        (
            vec![
                &b"failure a\n"[..],
                b"failure: a\n",
                b"error a\n",
                b"error: a\n",
                b"success a\n",
                b"success: a\n",
                b"successful a\n",
                b"successful: a\n",
                b"]\n",
            ],
            vec![
                Event::Text("failure a\n".into()),
                Event::Text("failure: a\n".into()),
                Event::Text("error a\n".into()),
                Event::Text("error: a\n".into()),
                Event::Text("success a\n".into()),
                Event::Text("success: a\n".into()),
                Event::Text("successful a\n".into()),
                Event::Text("successful: a\n".into()),
                Event::Text("]\n".into()),
            ],
        )
    }

    #[tokio::test]
    async fn end_keywords_before_test() {
        let (end_keywords, end_events) = end_keywords();
        let events = parse_stream(&end_keywords.join(&[][..])[..]).await;
        assert_eq!(&end_events[..], &events[..]);
    }

    #[tokio::test]
    async fn test_end_keywords_in_global() {
        let (end_keywords, end_events) = end_keywords();
        for outcome in ["success", "failure", "error"] {
            let outcome = format!("{} old mcdonald\n", outcome);
            let stream = [
                &b"test old mcdonald\n"[..],
                outcome.as_bytes(),
                &end_keywords.join(&[][..])[..],
            ];

            let events = dbg!(parse_stream(&stream.join(&[][..])[..]).await);
            assert_eq!(&end_events[..], &events[2..]);
        }
    }

    #[tokio::test]
    async fn test_end_keywords_in_test() {
        let (end_keywords, end_events) = end_keywords();
        let stream = [
            &b"test old mcdonald\n"[..],
            &b"test old mcdonald\n"[..], // duplicate
            &end_keywords.join(&[][..])[..],
            b"failure old mcdonald\n", // legitimate test end
        ];

        let events = dbg!(parse_stream(&stream.join(&[][..])[..]).await);

        let mut expected_events = vec![
            Event::TestStart("old mcdonald".into()),
            Event::Text("test old mcdonald\n".into()),
        ];
        expected_events.extend_from_slice(&end_events[..]);
        expected_events.push(Event::TestFailure("old mcdonald".into(), vec![]));
        assert_eq!(&expected_events[..], &events[..]);
    }

    #[tokio::test]
    async fn test_keywords_in_test() {
        let (end_keywords, end_events) = end_keywords();
        let stream = [
            &b"test old mcdonald\n"[..],
            &b"test old mcdonald\n"[..], // duplicate
            &end_keywords.join(&[][..])[..],
            b"failure old mcdonald\n", // legitimate test end
        ];

        let events = dbg!(parse_stream(&stream.join(&[][..])[..]).await);

        let mut expected_events = vec![
            Event::TestStart("old mcdonald".into()),
            Event::Text("test old mcdonald\n".into()),
        ];
        expected_events.extend_from_slice(&end_events[..]);
        expected_events.push(Event::TestFailure("old mcdonald".into(), vec![]));
        assert_eq!(&expected_events[..], &events[..]);
    }

    #[tokio::test]
    async fn test_keywords_in_brackets() {
        let (end_keywords, _end_events) = end_keywords();
        let in_details = String::from_utf8(
            [
                &b"test old mcdonald\n"[..], // duplicate to ignore
                &end_keywords[..end_keywords.len() - 1].join(&[][..])[..],
                &b" ]\n"[..], // false ending
            ]
            .join(&[][..]),
        )
        .unwrap();
        let stream = [
            &b"test old mcdonald\n"[..],
            &b"failure old mcdonald [\n"[..], // start a details section
            &in_details.as_bytes(),           // details with embedded commands
            &b"]\n"[..],                      // legitimate end of details
        ];

        let events = dbg!(parse_stream(&stream.join(&[][..])[..]).await);

        let expected_events = vec![
            Event::TestStart("old mcdonald".into()),
            Event::TestFailure(
                "old mcdonald".into(),
                vec![Part::new(
                    X_TRACEBACK,
                    TRACEBACK_NAME,
                    in_details.as_bytes(),
                )],
            ),
        ];
        assert_eq!(&expected_events[..], &events[..]);
    }

    #[tokio::test]
    async fn test_invalid_lines_passthrough() {
        let stream = &b"randombytes\n"[..];
        let events = parse_stream(&stream).await;
        assert_eq!(&[Event::Text("randombytes\n".into()),], &events[..]);
    }

    #[tokio::test]
    async fn test_empty_stream() {
        let stream = &b""[..];
        let events = parse_stream(&stream).await;
        assert_eq!(&[] as &[Event], &events[..]);
    }

    #[tokio::test]
    async fn test_end_stream_in_test() {
        let stream = [&b"test old mcdonald\n"[..]];

        let events = parse_stream(&stream.join(&[][..])[..]).await;
        assert_eq!(
            &[
                Event::TestStart("old mcdonald".into()),
                Event::TestError(
                    "old mcdonald".into(),
                    vec![Part::new(
                        X_TRACEBACK,
                        TRACEBACK_NAME,
                        "lost connection during test 'old mcdonald'".as_bytes()
                    )]
                ),
            ],
            &events[..]
        );
    }

    fn variant_event(variant: &str, name: &str, parts: &[Part]) -> Event {
        match variant {
            "error" => Event::TestError(name.into(), parts.to_vec()),
            "failure" => Event::TestFailure(name.into(), parts.to_vec()),
            "success" => Event::TestSuccess(name.into(), parts.to_vec()),
            "skip" => Event::TestSkip(name.into(), parts.to_vec()),
            "xfail" => Event::TestExpectedFailure(name.into(), parts.to_vec()),
            "uxsuccess" => Event::TestUnexpectedSuccess(name.into(), parts.to_vec()),
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn test_end_stream_after_test() {
        for variant in ["error", "failure", "success", "skip", "xfail", "uxsuccess"] {
            let input = &format!("{variant} old mcdonald\n");
            let stream = [&b"test old mcdonald\n"[..], input.as_bytes()];

            let events = parse_stream(&stream.join(&[][..])[..]).await;
            assert_eq!(
                &[
                    Event::TestStart("old mcdonald".into()),
                    variant_event(variant, "old mcdonald", &[]),
                ],
                &events[..]
            );
        }
    }

    #[tokio::test]
    async fn test_empty_bracket_content() {
        for variant in ["error", "failure", "success", "skip", "xfail", "uxsuccess"] {
            let input = &format!("{variant} old mcdonald [\n]\n");
            let stream = [&b"test old mcdonald\n"[..], input.as_bytes()];

            let events = parse_stream(&stream.join(&[][..])[..]).await;
            assert_eq!(
                &[
                    Event::TestStart("old mcdonald".into()),
                    variant_event(
                        variant,
                        "old mcdonald",
                        &[Part::new(X_TRACEBACK, TRACEBACK_NAME, "".as_bytes())]
                    ),
                ],
                &events[..]
            );
        }
    }

    #[tokio::test]
    async fn test_end_stream_in_brackets() {
        for outcome in ["error", "failure", "success", "skip", "xfail", "uxsuccess"] {
            for outcome_details in ["[", "[ multipart"] {
                let input = &format!("{} old mcdonald {}\n", outcome, outcome_details);
                let stream = [&b"test old mcdonald\n"[..], input.as_bytes()];

                let events = parse_stream(&stream.join(&[][..])[..]).await;
                assert_eq!(
                    &[
                        Event::TestStart("old mcdonald".into()),
                        Event::TestError(
                            "old mcdonald".into(),
                            vec![Part::new(
                                X_TRACEBACK,
                                TRACEBACK_NAME,
                                "lost connection during test 'old mcdonald'".as_bytes(),
                            )]
                        ),
                    ],
                    &events[..]
                );
            }
        }
    }

    #[tokio::test]
    async fn test_progress_events() {
        let stream = [
            &b"progress: push\n"[..],
            &b"progress: 23\n"[..],
            &b"progress: -2\n"[..],
            &b"progress: pop\n"[..],
            &b"progress: +4\n"[..],
        ];

        let events = parse_stream(&stream.join(&[][..])[..]).await;
        assert_eq!(
            &[
                Event::ProgressPush,
                Event::ProgressSet(23),
                Event::ProgressCurrent(-2),
                Event::ProgressPop,
                Event::ProgressCurrent(4),
            ],
            &events[..]
        );
    }

    #[tokio::test]
    async fn test_tag_events() {
        let stream = [
            &b"tags: foo bar:baz  quux\n"[..],
            &b"tags: foo -bar:baz  quux\n"[..],
            &b"test old mcdonald\n"[..],
            &b"tags: foo -bar:baz\n"[..],
            &b"success old mcdonald\n"[..],
        ];

        let events = parse_stream(&stream.join(&[][..])[..]).await;
        assert_eq!(
            &[
                Event::Tags(vec!["foo".into(), "bar:baz".into(), "quux".into()], vec![]),
                Event::Tags(vec!["foo".into(), "quux".into()], vec!["bar:baz".into()]),
                Event::TestStart("old mcdonald".into()),
                Event::Tags(vec!["foo".into()], vec!["bar:baz".into()]),
                Event::TestSuccess("old mcdonald".into(), vec![])
            ],
            &events[..]
        );
    }

    #[tokio::test]
    async fn test_time_events() {
        let stream = [
            // set it globally
            &b"time: 2001-12-12 12:59:59Z\n"[..],
            &b"test old mcdonald\n"[..],
            // and of course, how long did the test take requires setting it before an outcome
            &b"time: 2001-12-13 12:59:59Z\n"[..],
            &b"success old mcdonald\n"[..],
        ];

        let events = parse_stream(&stream.join(&[][..])[..]).await;
        assert_eq!(
            &[
                Event::Time(
                    NaiveDate::from_ymd_opt(2001, 12, 12)
                        .unwrap()
                        .and_hms_opt(12, 59, 59)
                        .unwrap()
                        .and_utc()
                ),
                Event::TestStart("old mcdonald".into()),
                Event::Time(
                    NaiveDate::from_ymd_opt(2001, 12, 13)
                        .unwrap()
                        .and_hms_opt(12, 59, 59)
                        .unwrap()
                        .and_utc()
                ),
                Event::TestSuccess("old mcdonald".into(), vec![])
            ],
            &events[..]
        );
    }
}
