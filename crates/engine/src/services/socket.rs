use crate::EngineError;
use coreshift_core::reactor::{Reactor, Token};
use coreshift_core::unix_socket::{
    PeerCred, UnixConnectResult, UnixListenerFd, UnixSocketAddr, UnixSocketBindOptions,
    UnixStreamFd, bind_unix_listener, connect_unix_stream,
};
use std::thread;

pub struct EngineUnixListener {
    inner: UnixListenerFd,
}

pub struct EngineUnixStream {
    inner: UnixStreamFd,
}

pub fn bind_abstract_stream_socket(name: &[u8]) -> Result<EngineUnixListener, EngineError> {
    Ok(EngineUnixListener {
        inner: bind_unix_listener(
            UnixSocketAddr::Abstract(name),
            UnixSocketBindOptions::default(),
        )?,
    })
}

pub fn connect_abstract_stream_socket(name: &[u8]) -> Result<EngineUnixStream, EngineError> {
    match connect_unix_stream(UnixSocketAddr::Abstract(name))? {
        UnixConnectResult::Connected(stream) => Ok(EngineUnixStream { inner: stream }),
        UnixConnectResult::InProgress(stream) => Ok(EngineUnixStream {
            inner: stream.finish_connect()?,
        }),
    }
}

impl EngineUnixListener {
    pub fn accept(&self) -> Result<Option<EngineUnixStream>, EngineError> {
        Ok(self.inner.accept()?.map(|inner| EngineUnixStream { inner }))
    }

    pub(crate) fn register_readable(&self, reactor: &mut Reactor) -> Result<Token, EngineError> {
        Ok(reactor.add(&self.inner.fd, true, false)?)
    }
}

impl EngineUnixStream {
    pub fn peer_cred(&self) -> Result<Option<PeerCred>, EngineError> {
        Ok(self.inner.peer_cred()?)
    }

    pub(crate) fn register_readable(&self, reactor: &mut Reactor) -> Result<Token, EngineError> {
        Ok(reactor.add(&self.inner.fd, true, false)?)
    }

    pub(crate) fn unregister_readable(&self, reactor: &Reactor) -> Result<(), EngineError> {
        Ok(reactor.del(&self.inner.fd)?)
    }

    pub fn read_some(&self, buf: &mut [u8]) -> Result<Option<usize>, EngineError> {
        Ok(self.inner.fd.read_slice(buf)?)
    }

    pub fn write_all(&self, mut buf: &[u8]) -> Result<(), EngineError> {
        while !buf.is_empty() {
            match self.inner.fd.write_slice(buf)? {
                Some(0) | None => thread::yield_now(),
                Some(n) => buf = &buf[n..],
            }
        }
        Ok(())
    }

    pub fn try_write_all(&self, buf: &[u8]) -> Result<bool, EngineError> {
        match self.inner.fd.write_slice(buf)? {
            Some(n) if n == buf.len() => Ok(true),
            Some(_) | None => Ok(false),
        }
    }

    pub fn read_line_blocking(&self, max_len: usize) -> Result<Option<Vec<u8>>, EngineError> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match self.read_some(&mut byte)? {
                Some(0) => return Ok(None),
                Some(_) => {
                    line.push(byte[0]);
                    if byte[0] == b'\n' {
                        return Ok(Some(line));
                    }
                    if line.len() >= max_len {
                        return Ok(Some(line));
                    }
                }
                None => thread::yield_now(),
            }
        }
    }
}
