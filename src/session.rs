use std::collections::VecDeque;

pub struct Scrollback {
    buf: VecDeque<u8>,
    max: usize,
}

impl Scrollback {
    pub fn new(max: usize) -> Self {
        Self { buf: VecDeque::new(), max }
    }

    pub fn push(&mut self, data: &[u8]) {
        for &b in data {
            if self.buf.len() >= self.max {
                self.buf.pop_front();
            }
            self.buf.push_back(b);
        }
    }

    pub fn snapshot(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_snapshot() {
        let mut sb = Scrollback::new(100);
        sb.push(b"hello");
        assert_eq!(sb.snapshot(), b"hello");
    }

    #[test]
    fn test_max_capacity_evicts_oldest() {
        let mut sb = Scrollback::new(5);
        sb.push(b"123456789"); // 9 bytes into 5-byte buffer
        assert_eq!(sb.len(), 5);
        assert_eq!(sb.snapshot(), b"56789");
    }

    #[test]
    fn test_empty_snapshot() {
        let sb = Scrollback::new(100);
        assert_eq!(sb.snapshot(), b"");
    }

    #[test]
    fn test_exact_capacity() {
        let mut sb = Scrollback::new(3);
        sb.push(b"abc");
        assert_eq!(sb.len(), 3);
        sb.push(b"d");
        assert_eq!(sb.snapshot(), b"bcd");
    }
}
