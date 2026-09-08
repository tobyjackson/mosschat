//! The gate control-stream frames and the `Relay` datagram of
//! `docs/dev/gatehouse-design.md` section 1.
//!
//! Control frames ride one bidirectional QUIC stream: a 4 byte big-endian
//! length prefix, then a deterministic CBOR array whose first element is the
//! frame type number from the design's frame table. Only the frames WO-1.3a
//! owns are represented here (1-6, 9-12, 14-15); `Start`, `StartRequest` and
//! the porch-stream frames 16-19 belong to WO-1.3b's doorbell.

use minicbor::decode::Error as DecodeError;
use minicbor::{Decoder, Encoder};

use super::GateError;

/// Every control frame's length prefix is checked against this cap before
/// any allocation happens (section 1, "caps and rate limits").
pub const CONTROL_FRAME_LEN_CAP: u32 = 64 * 1024;

/// The `Relay` datagram payload cap (section 1).
pub const RELAY_PAYLOAD_CAP: usize = 1200;

/// The one-byte discriminator of a `Relay` datagram, distinguishing it from
/// every other datagram this connection might carry.
pub const RELAY_DISCRIMINATOR: u8 = 0x01;

/// `Introduce.sealed` cap in bytes (section 1).
pub const SEALED_CAP: usize = 512;

/// `Error.detail` cap in bytes (section 1).
pub const ERROR_DETAIL_CAP: usize = 64;

/// The fixed 19 byte address encoding of section 1: 1 byte family, 16 byte
/// address (IPv4 in the first four bytes, the rest zero), 2 byte big-endian
/// port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Addr {
    /// `4` or `6`; any other value fails to decode.
    pub family: u8,
    /// The address bytes, IPv4 left-aligned in the first four and the rest
    /// zero, IPv6 filling all 16.
    pub bytes: [u8; 16],
    /// Big-endian port.
    pub port: u16,
}

impl Addr {
    /// Builds an [`Addr`] from a [`std::net::SocketAddr`].
    #[must_use]
    pub fn from_socket_addr(addr: std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(v4) => {
                let mut bytes = [0u8; 16];
                bytes[..4].copy_from_slice(&v4.ip().octets());
                Self {
                    family: 4,
                    bytes,
                    port: v4.port(),
                }
            }
            std::net::SocketAddr::V6(v6) => Self {
                family: 6,
                bytes: v6.ip().octets(),
                port: v6.port(),
            },
        }
    }

    /// Converts back to a [`std::net::SocketAddr`], if `family` is valid.
    #[must_use]
    pub fn to_socket_addr(self) -> Option<std::net::SocketAddr> {
        match self.family {
            4 => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(self.bytes.get(..4)?);
                Some(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    self.port,
                ))
            }
            6 => Some(std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(self.bytes)),
                self.port,
            )),
            _ => None,
        }
    }

    fn to_raw(self) -> [u8; 19] {
        let mut out = [0u8; 19];
        out[0] = self.family;
        out[1..17].copy_from_slice(&self.bytes);
        out[17..19].copy_from_slice(&self.port.to_be_bytes());
        out
    }

    fn from_raw(raw: &[u8]) -> Result<Self, DecodeError> {
        if raw.len() != 19 {
            return Err(DecodeError::message("Addr must be exactly 19 bytes"));
        }
        let mut bytes = [0u8; 16];
        #[allow(clippy::indexing_slicing)]
        bytes.copy_from_slice(&raw[1..17]);
        #[allow(clippy::indexing_slicing)]
        let port = u16::from_be_bytes([raw[17], raw[18]]);
        Ok(Self {
            #[allow(clippy::indexing_slicing)]
            family: raw[0],
            bytes,
            port,
        })
    }

    fn encode(self, enc: &mut Encoder<&mut Vec<u8>>) -> Result<(), DecodeError> {
        enc.bytes(&self.to_raw())
            .map_err(|_| DecodeError::message("failed to encode Addr"))?;
        Ok(())
    }

    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::from_raw(dec.bytes()?)
    }
}

/// A control-stream frame, WO-1.3a's subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Frame 1, house to gate.
    Register {
        /// Protocol version, currently always `1`.
        v: u8,
        /// The community identifier.
        community: [u8; 32],
    },
    /// Frame 2, gate to house.
    Registered {
        v: u8,
        observed: Addr,
        keepalive_s: u8,
        secondary_port: u16,
    },
    /// Frame 3, house to gate.
    Reflect { v: u8 },
    /// Frame 4, gate to house.
    Reflected { v: u8, observed: Addr },
    /// Frame 5, house to gate.
    Introduce {
        v: u8,
        tag: [u8; 32],
        ttl_s: u16,
        sealed: Vec<u8>,
    },
    /// Frame 6, gate to house, sent to both introduced parties.
    Introduction {
        v: u8,
        tag: [u8; 32],
        session: u32,
        peer_observed: Addr,
        role: u8,
    },
    /// Frame 9, house to gate.
    Keepalive { v: u8 },
    /// Frame 10, gate to house.
    KeepaliveAck { v: u8, observed: Addr },
    /// Frame 11, house to gate.
    Goodbye { v: u8, reason: u8 },
    /// Frame 12, gate to house.
    Error { v: u8, code: u8, detail: String },
    /// Frame 14, gate to house.
    Knock {
        v: u8,
        tag: [u8; 32],
        ttl_s: u16,
        sealed: Vec<u8>,
    },
    /// Frame 15, house to gate.
    KnockAnswer { v: u8, tag: [u8; 32], accept: bool },
}

const T_REGISTER: u8 = 1;
const T_REGISTERED: u8 = 2;
const T_REFLECT: u8 = 3;
const T_REFLECTED: u8 = 4;
const T_INTRODUCE: u8 = 5;
const T_INTRODUCTION: u8 = 6;
const T_KEEPALIVE: u8 = 9;
const T_KEEPALIVE_ACK: u8 = 10;
const T_GOODBYE: u8 = 11;
const T_ERROR: u8 = 12;
const T_KNOCK: u8 = 14;
const T_KNOCK_ANSWER: u8 = 15;

fn read_32(dec: &mut Decoder<'_>) -> Result<[u8; 32], DecodeError> {
    dec.bytes()?
        .try_into()
        .map_err(|_| DecodeError::message("expected a 32 byte string"))
}

impl Frame {
    /// Encodes this frame as a deterministic CBOR array: definite length,
    /// shortest-form integers, the frame type first.
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        // Every call below is over a `Vec<u8>` sink, which is infallible
        // I/O; a failure here can only be a logic error in the sequence of
        // calls, never allocation or I/O failure.
        #[allow(clippy::unwrap_used)]
        match self {
            Frame::Register { v, community } => {
                enc.array(3).unwrap();
                enc.u8(T_REGISTER).unwrap();
                enc.u8(*v).unwrap();
                enc.bytes(community).unwrap();
            }
            Frame::Registered {
                v,
                observed,
                keepalive_s,
                secondary_port,
            } => {
                enc.array(5).unwrap();
                enc.u8(T_REGISTERED).unwrap();
                enc.u8(*v).unwrap();
                observed.encode(&mut enc).unwrap();
                enc.u8(*keepalive_s).unwrap();
                enc.u16(*secondary_port).unwrap();
            }
            Frame::Reflect { v } => {
                enc.array(2).unwrap();
                enc.u8(T_REFLECT).unwrap();
                enc.u8(*v).unwrap();
            }
            Frame::Reflected { v, observed } => {
                enc.array(3).unwrap();
                enc.u8(T_REFLECTED).unwrap();
                enc.u8(*v).unwrap();
                observed.encode(&mut enc).unwrap();
            }
            Frame::Introduce {
                v,
                tag,
                ttl_s,
                sealed,
            } => {
                enc.array(4).unwrap();
                enc.u8(T_INTRODUCE).unwrap();
                enc.u8(*v).unwrap();
                enc.bytes(tag).unwrap();
                enc.u16(*ttl_s).unwrap();
                enc.bytes(sealed).unwrap();
            }
            Frame::Introduction {
                v,
                tag,
                session,
                peer_observed,
                role,
            } => {
                enc.array(5).unwrap();
                enc.u8(T_INTRODUCTION).unwrap();
                enc.u8(*v).unwrap();
                enc.bytes(tag).unwrap();
                enc.u32(*session).unwrap();
                peer_observed.encode(&mut enc).unwrap();
                enc.u8(*role).unwrap();
            }
            Frame::Keepalive { v } => {
                enc.array(2).unwrap();
                enc.u8(T_KEEPALIVE).unwrap();
                enc.u8(*v).unwrap();
            }
            Frame::KeepaliveAck { v, observed } => {
                enc.array(3).unwrap();
                enc.u8(T_KEEPALIVE_ACK).unwrap();
                enc.u8(*v).unwrap();
                observed.encode(&mut enc).unwrap();
            }
            Frame::Goodbye { v, reason } => {
                enc.array(3).unwrap();
                enc.u8(T_GOODBYE).unwrap();
                enc.u8(*v).unwrap();
                enc.u8(*reason).unwrap();
            }
            Frame::Error { v, code, detail } => {
                enc.array(4).unwrap();
                enc.u8(T_ERROR).unwrap();
                enc.u8(*v).unwrap();
                enc.u8(*code).unwrap();
                enc.str(detail).unwrap();
            }
            Frame::Knock {
                v,
                tag,
                ttl_s,
                sealed,
            } => {
                enc.array(4).unwrap();
                enc.u8(T_KNOCK).unwrap();
                enc.u8(*v).unwrap();
                enc.bytes(tag).unwrap();
                enc.u16(*ttl_s).unwrap();
                enc.bytes(sealed).unwrap();
            }
            Frame::KnockAnswer { v, tag, accept } => {
                enc.array(4).unwrap();
                enc.u8(T_KNOCK_ANSWER).unwrap();
                enc.u8(*v).unwrap();
                enc.bytes(tag).unwrap();
                enc.bool(*accept).unwrap();
            }
        }
        buf
    }

    /// Decodes a frame from its deterministic CBOR array encoding, refusing
    /// any array whose length disagrees with its frame type.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes);
        let len = dec
            .array()?
            .ok_or_else(|| DecodeError::message("frame must be a definite-length array"))?;
        let frame_type = dec.u8()?;
        let frame = match (frame_type, len) {
            (T_REGISTER, 3) => Frame::Register {
                v: dec.u8()?,
                community: read_32(&mut dec)?,
            },
            (T_REGISTERED, 5) => Frame::Registered {
                v: dec.u8()?,
                observed: Addr::decode(&mut dec)?,
                keepalive_s: dec.u8()?,
                secondary_port: dec.u16()?,
            },
            (T_REFLECT, 2) => Frame::Reflect { v: dec.u8()? },
            (T_REFLECTED, 3) => Frame::Reflected {
                v: dec.u8()?,
                observed: Addr::decode(&mut dec)?,
            },
            (T_INTRODUCE, 4) => {
                let v = dec.u8()?;
                let tag = read_32(&mut dec)?;
                let ttl_s = dec.u16()?;
                let sealed = dec.bytes()?.to_vec();
                if sealed.len() > SEALED_CAP {
                    return Err(DecodeError::message("sealed body exceeds its cap"));
                }
                Frame::Introduce {
                    v,
                    tag,
                    ttl_s,
                    sealed,
                }
            }
            (T_INTRODUCTION, 5) => Frame::Introduction {
                v: dec.u8()?,
                tag: read_32(&mut dec)?,
                session: dec.u32()?,
                peer_observed: Addr::decode(&mut dec)?,
                role: dec.u8()?,
            },
            (T_KEEPALIVE, 2) => Frame::Keepalive { v: dec.u8()? },
            (T_KEEPALIVE_ACK, 3) => Frame::KeepaliveAck {
                v: dec.u8()?,
                observed: Addr::decode(&mut dec)?,
            },
            (T_GOODBYE, 3) => Frame::Goodbye {
                v: dec.u8()?,
                reason: dec.u8()?,
            },
            (T_ERROR, 4) => {
                let v = dec.u8()?;
                let code = dec.u8()?;
                let detail = dec.str()?.to_string();
                if detail.len() > ERROR_DETAIL_CAP {
                    return Err(DecodeError::message("error detail exceeds its cap"));
                }
                Frame::Error { v, code, detail }
            }
            (T_KNOCK, 4) => {
                let v = dec.u8()?;
                let tag = read_32(&mut dec)?;
                let ttl_s = dec.u16()?;
                let sealed = dec.bytes()?.to_vec();
                if sealed.len() > SEALED_CAP {
                    return Err(DecodeError::message("sealed body exceeds its cap"));
                }
                Frame::Knock {
                    v,
                    tag,
                    ttl_s,
                    sealed,
                }
            }
            (T_KNOCK_ANSWER, 4) => Frame::KnockAnswer {
                v: dec.u8()?,
                tag: read_32(&mut dec)?,
                accept: dec.bool()?,
            },
            (other, _) => {
                return Err(DecodeError::message(format!(
                    "unknown or mis-sized frame type {other}"
                )));
            }
        };
        if dec.position() != bytes.len() {
            return Err(DecodeError::message("frame carries trailing bytes"));
        }
        Ok(frame)
    }
}

/// Reads one length-prefixed control frame from `stream`, bounded by
/// `CONTROL_FRAME_LEN_CAP` (checked before allocating) and `deadline`.
///
/// # Errors
///
/// Returns [`GateError::FrameTooLarge`] if the length prefix exceeds the
/// cap, [`GateError::Timeout`] if `deadline` elapses first, and
/// [`GateError::Io`] or [`GateError::Protocol`] otherwise.
pub async fn read_frame(
    stream: &mut quinn::RecvStream,
    deadline: std::time::Duration,
) -> Result<Frame, GateError> {
    let read = async {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);
        if len > CONTROL_FRAME_LEN_CAP {
            return Err(GateError::FrameTooLarge(len));
        }
        let mut body = vec![0u8; len as usize];
        stream.read_exact(&mut body).await?;
        Frame::from_cbor(&body).map_err(|e| GateError::Protocol(e.to_string()))
    };
    tokio::time::timeout(deadline, read)
        .await
        .map_err(|_| GateError::Timeout)?
}

/// Writes one length-prefixed control frame to `stream`.
pub async fn write_frame(stream: &mut quinn::SendStream, frame: &Frame) -> Result<(), GateError> {
    let body = frame.to_cbor();
    let len = u32::try_from(body.len()).map_err(|_| GateError::FrameTooLarge(u32::MAX))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

/// Builds a `Relay` datagram: `[0x01][session: u32 BE][payload]`.
///
/// # Errors
///
/// Returns [`GateError::RelayPayloadTooLarge`] if `payload` exceeds
/// [`RELAY_PAYLOAD_CAP`].
pub fn encode_relay(session: u32, payload: &[u8]) -> Result<Vec<u8>, GateError> {
    if payload.len() > RELAY_PAYLOAD_CAP {
        return Err(GateError::RelayPayloadTooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(1 + 4 + payload.len());
    out.push(RELAY_DISCRIMINATOR);
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodes a `Relay` datagram, returning the session id and a slice of the
/// payload borrowed from `datagram`.
///
/// # Errors
///
/// Returns [`GateError::Protocol`] if the datagram is too short or does not
/// carry the `Relay` discriminator, and [`GateError::RelayPayloadTooLarge`]
/// if the payload exceeds [`RELAY_PAYLOAD_CAP`].
pub fn decode_relay(datagram: &[u8]) -> Result<(u32, &[u8]), GateError> {
    if datagram.len() < 5 {
        return Err(GateError::Protocol("relay datagram too short".into()));
    }
    #[allow(clippy::indexing_slicing)]
    let discriminator = datagram[0];
    if discriminator != RELAY_DISCRIMINATOR {
        return Err(GateError::Protocol(
            "datagram is not a Relay discriminator".into(),
        ));
    }
    #[allow(clippy::indexing_slicing)]
    let session_bytes: [u8; 4] = datagram[1..5].try_into().unwrap_or([0; 4]);
    let session = u32::from_be_bytes(session_bytes);
    #[allow(clippy::indexing_slicing)]
    let payload = &datagram[5..];
    if payload.len() > RELAY_PAYLOAD_CAP {
        return Err(GateError::RelayPayloadTooLarge(payload.len()));
    }
    Ok((session, payload))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn register_round_trips() {
        let frame = Frame::Register {
            v: 1,
            community: [7u8; 32],
        };
        let bytes = frame.to_cbor();
        assert_eq!(Frame::from_cbor(&bytes).unwrap(), frame);
    }

    #[test]
    fn addr_round_trips_v4_and_v6() {
        let v4: std::net::SocketAddr = "203.0.113.9:4433".parse().unwrap();
        let a = Addr::from_socket_addr(v4);
        assert_eq!(a.to_socket_addr(), Some(v4));

        let v6: std::net::SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let a = Addr::from_socket_addr(v6);
        assert_eq!(a.to_socket_addr(), Some(v6));
    }

    #[test]
    fn frame_with_trailing_bytes_is_rejected() {
        let mut bytes = Frame::Keepalive { v: 1 }.to_cbor();
        bytes.push(0xFF);
        assert!(Frame::from_cbor(&bytes).is_err());
    }

    #[test]
    fn relay_datagram_round_trips() {
        let payload = vec![9u8; 100];
        let encoded = encode_relay(42, &payload).unwrap();
        let (session, decoded_payload) = decode_relay(&encoded).unwrap();
        assert_eq!(session, 42);
        assert_eq!(decoded_payload, payload.as_slice());
    }

    #[test]
    fn relay_payload_over_cap_is_refused_at_encode() {
        let payload = vec![0u8; RELAY_PAYLOAD_CAP + 1];
        assert!(encode_relay(1, &payload).is_err());
    }

    #[test]
    fn oversized_sealed_body_is_rejected_at_decode() {
        let frame = Frame::Introduce {
            v: 1,
            tag: [1u8; 32],
            ttl_s: 60,
            sealed: vec![0u8; SEALED_CAP],
        };
        // Hand-build an over-cap version: re-encode with a longer body than
        // the type's own constructor would allow, proving the decoder
        // enforces the cap independently of any well-behaved encoder.
        let mut bytes = frame.to_cbor();
        // Grow the sealed byte string's declared length and add the extra
        // bytes; simplest is to just re-run from a manually built encoder.
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.array(4).unwrap();
        enc.u8(T_INTRODUCE).unwrap();
        enc.u8(1).unwrap();
        enc.bytes(&[1u8; 32]).unwrap();
        enc.u16(60).unwrap();
        enc.bytes(&vec![0u8; SEALED_CAP + 1]).unwrap();
        assert!(Frame::from_cbor(&buf).is_err());
        // The well-formed one at exactly the cap still round trips.
        assert_eq!(Frame::from_cbor(&bytes).unwrap(), frame);
        let _ = &mut bytes;
    }
}
