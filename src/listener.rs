use crate::tcp::{TcpConnection, TcpError};
use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

pub struct PeerListener {
    listener: TcpListener,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl PeerListener {
    pub fn bind(
        address: SocketAddr,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, ListenerError> {
        Ok(Self {
            listener: TcpListener::bind(address).map_err(ListenerError::Io)?,
            read_timeout,
            write_timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        self.listener.local_addr().map_err(ListenerError::Io)
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> Result<(), ListenerError> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(ListenerError::Io)
    }

    pub(crate) fn try_accept(&self) -> Result<Option<(TcpConnection, SocketAddr)>, ListenerError> {
        match self.listener.accept() {
            Ok((stream, address)) => {
                let connection =
                    TcpConnection::from_stream(stream, self.read_timeout, self.write_timeout)
                        .map_err(ListenerError::Tcp)?;
                Ok(Some((connection, address)))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(ListenerError::Io(error)),
        }
    }

    pub fn accept(&self) -> Result<(TcpConnection, SocketAddr), ListenerError> {
        let (stream, address) = self.listener.accept().map_err(ListenerError::Io)?;
        let connection = TcpConnection::from_stream(stream, self.read_timeout, self.write_timeout)
            .map_err(ListenerError::Tcp)?;
        Ok((connection, address))
    }
}

#[derive(Debug)]
pub enum ListenerError {
    Io(io::Error),
    Tcp(TcpError),
}

impl fmt::Display for ListenerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "listener I/O failed: {error}"),
            Self::Tcp(error) => write!(f, "accepted connection setup failed: {error}"),
        }
    }
}

impl std::error::Error for ListenerError {}
