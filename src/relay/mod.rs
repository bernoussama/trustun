use crate::sans_io::SansIo;

pub struct RelayFrame {
    frame_type: FrameType,
    payload: Vec<u8>,
    output: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    SendPacket = 1,
    RecvPacket = 2,
    Ping = 3,
    Pong = 4,
    PeerPresent = 5,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayError {
    #[error("relay payload too large: {0} bytes")]
    PayloadTooLarge(usize),
}

impl RelayFrame {
    #[must_use]
    pub fn new(frame_type: FrameType) -> Self {
        Self {
            frame_type,
            payload: Vec::new(),
            output: Vec::new(),
        }
    }

    #[must_use]
    pub fn frame_type(&self) -> FrameType {
        self.frame_type
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl SansIo for RelayFrame {
    type Error = RelayError;

    fn consume(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let length =
            u32::try_from(input.len()).map_err(|_| RelayError::PayloadTooLarge(input.len()))?;

        let mut staged = Vec::with_capacity(1 + std::mem::size_of::<u32>() + input.len());
        staged.push(self.frame_type as u8);
        staged.extend_from_slice(&length.to_be_bytes());
        staged.extend_from_slice(input);

        self.payload.clear();
        self.payload.extend_from_slice(input);
        self.output.extend_from_slice(&staged);

        Ok(())
    }

    fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_emits_frame_type_length_and_payload() {
        let mut frame = RelayFrame::new(FrameType::SendPacket);

        frame.consume(b"abc").unwrap();

        assert_eq!(frame.payload(), b"abc");
        assert_eq!(frame.take_output(), vec![1, 0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn consume_writes_payload_length_in_big_endian_order() {
        let mut frame = RelayFrame::new(FrameType::PeerPresent);

        frame.consume(&vec![0; 258]).unwrap();

        let output = frame.take_output();
        assert_eq!(&output[..5], &[5, 0, 0, 1, 2]);
        assert_eq!(output.len(), 5 + 258);
    }

    #[test]
    fn take_output_drains_pending_bytes() {
        let mut frame = RelayFrame::new(FrameType::Ping);

        frame.consume(b"").unwrap();

        assert_eq!(frame.take_output(), vec![3, 0, 0, 0, 0]);
        assert_eq!(frame.take_output(), Vec::<u8>::new());
    }
}
