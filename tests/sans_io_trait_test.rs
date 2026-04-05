use std::convert::Infallible;

use opentun::sans_io::SansIo;

#[derive(Default)]
struct UppercaseMachine {
    output: Vec<u8>,
}

impl SansIo for UppercaseMachine {
    type Error = Infallible;

    fn consume(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        for byte in input {
            self.output.push(byte.to_ascii_uppercase());
        }

        Ok(())
    }

    fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TestError {
    InvalidByte,
}

#[derive(Default)]
struct FallibleMachine {
    output: Vec<u8>,
}

impl SansIo for FallibleMachine {
    type Error = TestError;

    fn consume(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let mut staged = Vec::with_capacity(input.len());

        for byte in input {
            if *byte == b'!' {
                return Err(TestError::InvalidByte);
            }

            staged.push(*byte);
        }

        self.output.extend_from_slice(&staged);

        Ok(())
    }

    fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }
}

#[test]
fn consume_builds_output_stream_in_internal_buffer() {
    let mut machine = UppercaseMachine::default();

    machine.consume(b"hello").unwrap();
    machine.consume(b" world").unwrap();

    assert_eq!(machine.take_output(), b"HELLO WORLD".to_vec());
}

#[test]
fn take_output_extracts_and_clears_pending_bytes() {
    let mut machine = UppercaseMachine::default();

    machine.consume(b"abc").unwrap();

    assert_eq!(machine.take_output(), b"ABC".to_vec());
    assert_eq!(machine.take_output(), Vec::<u8>::new());
}

#[test]
fn consume_error_does_not_append_partial_output() {
    let mut machine = FallibleMachine::default();

    machine.consume(b"ok").unwrap();

    assert_eq!(machine.consume(b"no!pe"), Err(TestError::InvalidByte));
    assert_eq!(machine.take_output(), b"ok".to_vec());
}
