pub trait SansIo {
    type Error;

    fn output_buffer(&mut self) -> &mut Vec<u8>;

    fn consume(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    fn produce(&mut self, bytes: &[u8]) {
        self.output_buffer().extend_from_slice(bytes);
    }

    fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(self.output_buffer())
    }
}
