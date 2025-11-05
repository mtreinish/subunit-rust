Subunit Rust
============
[![subunit-rust CI][ci-image]][ci]
[![subunit on crates.io][cratesio-image]][cratesio]

[ci-image]: https://github.com/mtreinish/subunit-rust/actions/workflows/main.yml/badge.svg
[ci]: https://github.com/mtreinish/subunit-rust/actions/workflows/main.yml
[cratesio-image]: https://img.shields.io/crates/v/subunit.svg
[cratesio]: https://crates.io/crates/subunit

This repo contains a implementation of the subunit v2 protocol in Rust. It
provides an interface for both writing and reading subunit streams natively in
rust. The subunit v2 protocol is documented in the
[testing-cabal/subunit](https://github.com/testing-cabal/subunit/blob/master/README.rst#version-2)
repository.

## Reading subunit packets

Reading subunit packets first requires an object implementing the Read trait
containing the subunit stream. The parse_subunit() function is used to first
buffer the entire stream in memory, and then parse the contents and return
a vector of Event structs. For example, parsing a subunit stream from a file:
```rust
    let mut f = File::open("results.subunit")?;
    let events = parse_subunit(f).unwrap();
```
In this example, the `results.subunit` file will be opened and parsed with an
Event struct in the events vector for each subunit packet in the file.


## Writing subunit packets

Writing a subunit packet first requires creating an event structure to describe
the contents of the packet. For example:

```rust
    let mut event_start = Event {
        status: Some("inprogress".to_string()),
        test_id: Some("A_test_id".to_string()),
        timestamp: Some(Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11).unwrap()),
        tags: Some(vec!["tag_a".to_string(), "tag_b".to_string()]),
        file_content: None,
        file_name: None,
        mime_type: None,
        route_code: None
    };
```

A typical test event normally involves 2 packets though, one to mark the start
and the other to mark the finish of a test:
```rust
    let mut event_end = Event {
        status: Some("success".to_string()),
        test_id: Some("A_test_id".to_string()),
        timestamp: Some(Utc.with_ymd_and_hms(2014, 7, 8, 9, 12, 0).unwrap()),
        tags: Some(vec!["tag_a".to_string(), "tag_b".to_string()]),
        file_content: Some("stdout content".to_string().into_bytes()),
        file_name: Some("stdout:''".to_string()),
        mime_type: Some("text/plain;charset=utf8".to_string()),
        route_code: None
    };
```
Then you'll want to write the packet out to something. Anything that implements
the std::io::Write trait can be used for the packets, including things like a
File and a TCPStream. In this case we'll use Vec<u8> to keep it in memory:
```rust
    let mut subunit_stream: Vec<u8> = Vec::new();

    subunit_stream = event_start.write(subunit_stream)?;
    subunit_stream = event_end.write(subunit_stream)?;
```
With this the subunit_stream buffer will contain the contents of the subunit
stream for that test event.
