/// A state machine that consumes bytes and accumulates emitted bytes internally.
pub trait SansIo {
    type Error;

    /// Consumes input and appends any emitted bytes to pending output.
    ///
    /// Implementations must treat output as transactional: if this method returns
    /// `Err`, `take_output()` must observe the same pending bytes it would have
    /// seen before the failed call.
    fn consume(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Drains the bytes emitted by prior successful `consume()` calls.
    #[must_use]
    fn take_output(&mut self) -> Vec<u8>;
}
