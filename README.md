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
containing the subunit stream. The iter_stream() function is used to parse
the contents and return an iterator of ScannedItem enums. For example,
parsing a subunit stream from a file:
```rust,no_run
    use std::fs::File;
    use subunit::io::sync::iter_stream;
    use subunit::types::stream::ScannedItem;

    let f = File::open("results.subunit")?;
    for item in iter_stream(f) {
        match item? {
            ScannedItem::Event(event) => {
                // Process the event
                println!("Got event: {:?}", event);
            },
            ScannedItem::UTF8chars(text) => {
                // Process text
                println!("Got text: {:?}", text);
            },
            ScannedItem::Unknown(bytes, err) => {
                // Handle unknown data
                eprintln!("Unknown data: {:?}", err);
            },
        }
    }
    # Ok::<(), Box<dyn std::error::Error>>(())
```
In this example, the `results.subunit` file will be opened and parsed with a
ScannedItem for each packet in the file.


## Writing subunit packets

Writing a subunit packet first requires creating an event structure to describe
the contents of the packet. The Event API uses a builder pattern for
construction. For example:

```rust
    use subunit::types::{event::Event, teststatus::TestStatus};
    use chrono::{TimeZone, Utc};

    let event_start = Event::new(TestStatus::InProgress)
        .test_id("A_test_id")
        .datetime(Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11).unwrap())?
        .tag("tag_a")
        .tag("tag_b")
        .build();
    # Ok::<(), Box<dyn std::error::Error>>(())
```

A typical test event normally involves 2 packets though, one to mark the start
and the other to mark the finish of a test:
```rust
    use subunit::types::{event::Event, teststatus::TestStatus};
    use chrono::{TimeZone, Utc};

    let event_end = Event::new(TestStatus::Success)
        .test_id("A_test_id")
        .datetime(Utc.with_ymd_and_hms(2014, 7, 8, 9, 12, 0).unwrap())?
        .tag("tag_a")
        .tag("tag_b")
        .mime_type("text/plain;charset=utf8")
        .file_content("stdout:''", b"stdout content")
        .build();
    # Ok::<(), Box<dyn std::error::Error>>(())
```
Then you'll want to write the packet out to something. Anything that implements
the std::io::Write trait can be used for the packets, including things like a
File and a TCPStream. In this case we'll use Vec<u8> to keep it in memory:
```rust
    use subunit::serialize::Serializable;
    use subunit::types::{event::Event, teststatus::TestStatus};
    use chrono::{TimeZone, Utc};

    let mut subunit_stream: Vec<u8> = Vec::new();

    let event_start = Event::new(TestStatus::InProgress)
        .test_id("A_test_id")
        .datetime(Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11).unwrap())?
        .tag("tag_a")
        .tag("tag_b")
        .build();

    let event_end = Event::new(TestStatus::Success)
        .test_id("A_test_id")
        .datetime(Utc.with_ymd_and_hms(2014, 7, 8, 9, 12, 0).unwrap())?
        .tag("tag_a")
        .tag("tag_b")
        .mime_type("text/plain;charset=utf8")
        .file_content("stdout:''", b"stdout content")
        .build();

    event_start.serialize(&mut subunit_stream)?;
    event_end.serialize(&mut subunit_stream)?;
    # Ok::<(), Box<dyn std::error::Error>>(())
```
With this the subunit_stream buffer will contain the contents of the subunit
stream for that test event.
