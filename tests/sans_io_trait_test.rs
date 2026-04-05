use std::convert::Infallible;

use opentun::sans_io::SansIo;

#[derive(Default)]
struct UppercaseMachine {
    output: Vec<u8>,
}

impl SansIo for UppercaseMachine {
    type Error = Infallible;

    fn output_buffer(&mut self) -> &mut Vec<u8> {
        &mut self.output
    }

    fn consume(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        for byte in input {
            self.produce(&[byte.to_ascii_uppercase()]);
        }

        Ok(())
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
