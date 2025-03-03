#![allow(missing_docs)]
//! # Postcard-RPC Header Format
//!
//! Postcard-RPC's header is made up of three main parts:
//!
//! 1. A one-byte discriminant
//! 2. A 1-8 byte "Key"
//! 3. A 1-4 byte "Sequence Number"
//!
//! The Postcard-RPC Header is NOT encoded using `postcard`'s wire format.
//!
//! ## Discriminant
//!
//! The discriminant field is always one byte, and consists of three subfields
//! in the form `0bNNMM_VVVV`.
//!
//! * The two msbits are "key length", where the two N length bits represent
//!   a key length of 2^N. All values are valid.
//! * The next two msbits are "sequence number length", where the two M length
//!   bits represent a sequence number length of 2^M. Values 00, 01, and 10
//!   are valid.
//! * The four lsbits are "protocol version", where the four V version bits
//!   represent an unsigned 4-bit number. Currently only 0000 is a valid value.
//!
//! ## Key
//!
//! The Key consists of an fnv1a hash of the path string and schema of the
//! contained message. These are calculated using the [`hash` module](crate::hash),
//! and are natively calculated as an 8-byte hash.
//!
//! Keys may be encoded with variable fidelity on the wire, as follows:
//!
//! * For 8-byte keys, all key bytes appear in the form `[A, B, C, D, E, F, G, H]`.
//! * For 4-byte keys, the 8-byte form is compressed as `[A^B, C^D, E^F, G^H]`.
//! * For 2-byte keys, the 8-byte form is compressed as `[A^B^C^D, E^F^G^H]`.
//! * For 1-byte keys, the 8-byte form is compressed as `A^B^C^D^E^F^G^H`.
//!
//! The length of the Key is determined by the two `NN` bits in the discriminant.
//!
//! The length of the key is usually chosen by the **Server**, as the server is
//! able to calculate the minimum number of bits necessary to avoid collisions.
//!
//! When Clients receive a server response, they shall note the Key length used,
//! and match that for all subsequent messages. When Clients make first connection,
//! they shall use the 8-byte form by default.
//!
//! ## Sequence Number
//!
//! The Sequence Number is an unsigned integer used to match request-response pairs,
//! and disambiguate between multiple in-flight messages.
//!
//! Sequence Numbers may be encoded with variable fidelity on the wire, always in
//! little-endian order, of 1, 2, or 4 bytes.
//!
//! The length of the Sequence Number is determined by the two `MM` bits in the
//! discriminant.
//!
//! The length of the key is chosen by the "originator" of the message. For Endpoints
//! this is the client making the request. For Topics, this is the device sending the
//! topic message.

use crate::{Deserialize, Serialize};
use crate::{Key, Key1, Key2, Key4};
use core::marker::PhantomData;

//////////////////////////////////////////////////////////////////////////////
// FRAME
//////////////////////////////////////////////////////////////////////////////
///
/// A single postcard-rpc frame
#[derive(Clone)]
pub struct RpcMessage<'a, Mode: HeaderMode + Clone> {
    /// The wire header
    pub header: Mode::HeaderType,
    /// The serialized message payload
    #[cfg(feature = "use-std")]
    pub body: Vec<u8>,
    #[cfg(not(feature = "use-std"))]
    pub body: &'a [u8],
    /// Phantom data to keep track of the mode
    pub _hm: PhantomData<Mode>,
    /// Holds the lifetime
    pub _lifetime: PhantomData<&'a ()>,
}

impl<'a, Mode> RpcMessage<'a, Mode>
where
    Mode: HeaderMode,
{
    /// New from header and body
    #[cfg(feature = "use-std")]
    pub fn new(header: Mode::HeaderType) -> Self {
        Self {
            header,
            body: Vec::new(),
            _hm: PhantomData,
            _lifetime: PhantomData,
        }
    }

    #[cfg(feature = "use-std")]
    pub fn with_body(&self, body: Vec<u8>) -> RpcMessage<'a, Mode> {
        Self {
            header: self.header,
            body,
            _hm: PhantomData,
            _lifetime: PhantomData,
        }
    }

    #[cfg(not(feature = "use-std"))]
    pub fn new(header: Mode::HeaderType, body: &'a [u8]) -> Self {
        Self {
            header,
            body,
            _hm: PhantomData,
            _lifetime: PhantomData,
        }
    }

    #[cfg(not(feature = "use-std"))]
    pub fn with_body(&self, body: &'a [u8]) -> RpcMessage<'a, Mode> {
        Self {
            header: self.header,
            body,
            _hm: PhantomData,
            _lifetime: PhantomData,
        }
    }

    /// Serialize the `RpcMessage` into a Vec of bytes
    #[cfg(feature = "use-std")]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = self.header.write_to_vec();
        out.extend_from_slice(&self.body);
        out
    }

    #[cfg(feature = "use-std")]
    pub fn from_vec(buf: &'a mut Vec<u8>) -> Option<Self> {
        let slice: &'a mut [u8] = buf.as_mut_slice();
        Mode::HeaderType::take_from_slice(slice).map(|(header, rest)| Self {
            header,
            body: rest.to_vec(),
            _hm: PhantomData,
            _lifetime: PhantomData,
        })
    }

    /// Serialize the `RpcMessage` into a slice of bytes
    pub fn to_slice(&self, buf: &mut [u8]) {
        self.header.write_to_slice(buf).map(|(_header, rest)| {
            rest.copy_from_slice(&self.body);
        });
    }

    /// Deserialize an `RpcMessage` from a slice of bytes
    pub fn from_slice(buf: &'a mut [u8]) -> Option<Self> {
        Mode::HeaderType::take_from_slice(buf).map(|(header, rest)| Self {
            header,
            #[cfg(feature = "use-std")]
            body: rest.to_vec(),
            #[cfg(not(feature = "use-std"))]
            body: rest,
            _hm: PhantomData,
            _lifetime: PhantomData,
        })
    }
}

//////////////////////////////////////////////////////////////////////////////
// VARKEY
//////////////////////////////////////////////////////////////////////////////

/// A variably sized header Key
///
/// NOTE: We DO NOT impl Serialize/Deserialize for this type because
/// we use non-postcard-compatible format (externally tagged) on the wire.
///
/// NOTE: VarKey implements `PartialEq` by reducing two VarKeys down to the
/// smaller of the two forms, and checking whether they match. This allows
/// a key in 8-byte form to be compared to a key in 1, 2, or 4-byte form
/// for equality.
#[derive(Debug, Copy, Clone)]
pub enum VarKey {
    /// A one byte key
    Key1(Key1),
    /// A two byte key
    Key2(Key2),
    /// A four byte key
    Key4(Key4),
    /// An eight byte key
    Key8(Key),
}

/// We implement PartialEq MANUALLY for VarKey, because keys of different lengths SHOULD compare
/// as equal.
impl PartialEq for VarKey {
    fn eq(&self, other: &Self) -> bool {
        // figure out the minimum length
        match (self, other) {
            // Matching kinds
            (VarKey::Key1(self_key), VarKey::Key1(other_key)) => self_key.0.eq(&other_key.0),
            (VarKey::Key2(self_key), VarKey::Key2(other_key)) => self_key.0.eq(&other_key.0),
            (VarKey::Key4(self_key), VarKey::Key4(other_key)) => self_key.0.eq(&other_key.0),
            (VarKey::Key8(self_key), VarKey::Key8(other_key)) => {
                self_key.to_bytes().eq(&other_key.to_bytes())
            }

            // For the rest of the options, degrade the LARGER key to the SMALLER key, and then
            // check for equivalence after that.
            (VarKey::Key1(this), VarKey::Key2(other)) => {
                let other = Key1::from_key2(*other);
                this.0.eq(&other.0)
            }
            (VarKey::Key1(this), VarKey::Key4(other)) => {
                let other = Key1::from_key4(*other);
                this.0.eq(&other.0)
            }
            (VarKey::Key1(this), VarKey::Key8(other)) => {
                let other = Key1::from_key8(*other);
                this.0.eq(&other.0)
            }
            (VarKey::Key2(this), VarKey::Key1(other)) => {
                let this = Key1::from_key2(*this);
                this.0.eq(&other.0)
            }
            (VarKey::Key2(this), VarKey::Key4(other)) => {
                let other = Key2::from_key4(*other);
                this.0.eq(&other.0)
            }
            (VarKey::Key2(this), VarKey::Key8(other)) => {
                let other = Key2::from_key8(*other);
                this.0.eq(&other.0)
            }
            (VarKey::Key4(this), VarKey::Key1(other)) => {
                let this = Key1::from_key4(*this);
                this.0.eq(&other.0)
            }
            (VarKey::Key4(this), VarKey::Key2(other)) => {
                let this = Key2::from_key4(*this);
                this.0.eq(&other.0)
            }
            (VarKey::Key4(this), VarKey::Key8(other)) => {
                let other = Key4::from_key8(*other);
                this.0.eq(&other.0)
            }
            (VarKey::Key8(this), VarKey::Key1(other)) => {
                let this = Key1::from_key8(*this);
                this.0.eq(&other.0)
            }
            (VarKey::Key8(this), VarKey::Key2(other)) => {
                let this = Key2::from_key8(*this);
                this.0.eq(&other.0)
            }
            (VarKey::Key8(this), VarKey::Key4(other)) => {
                let this = Key4::from_key8(*this);
                this.0.eq(&other.0)
            }
        }
    }
}

impl VarKey {
    /// Keys can not be reaised, but instead only shrunk.
    ///
    /// This method will shrink to the requested length if that length is
    /// smaller than the current representation, or if the requested length
    /// is the same or larger than the current representation, it will be
    /// kept unchanged
    pub fn shrink_to(&mut self, kind: VarKeyKind) {
        match (&self, kind) {
            (VarKey::Key1(_), _) => {
                // Nothing to shrink
            }
            (VarKey::Key2(key2), VarKeyKind::Key1) => {
                *self = VarKey::Key1(Key1::from_key2(*key2));
            }
            (VarKey::Key2(_), _) => {
                // We are already as small or smaller than the request
            }
            (VarKey::Key4(key4), VarKeyKind::Key1) => {
                *self = VarKey::Key1(Key1::from_key4(*key4));
            }
            (VarKey::Key4(key4), VarKeyKind::Key2) => {
                *self = VarKey::Key2(Key2::from_key4(*key4));
            }
            (VarKey::Key4(_), _) => {
                // We are already as small or smaller than the request
            }
            (VarKey::Key8(key), VarKeyKind::Key1) => {
                *self = VarKey::Key1(Key1::from_key8(*key));
            }
            (VarKey::Key8(key), VarKeyKind::Key2) => {
                *self = VarKey::Key2(Key2::from_key8(*key));
            }
            (VarKey::Key8(key), VarKeyKind::Key4) => {
                *self = VarKey::Key4(Key4::from_key8(*key));
            }
            (VarKey::Key8(_), VarKeyKind::Key8) => {
                // Nothing to do
            }
        }
    }

    /// The current kind/length of the key
    pub fn kind(&self) -> VarKeyKind {
        match self {
            VarKey::Key1(_) => VarKeyKind::Key1,
            VarKey::Key2(_) => VarKeyKind::Key2,
            VarKey::Key4(_) => VarKeyKind::Key4,
            VarKey::Key8(_) => VarKeyKind::Key8,
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// VARKEYKIND
//////////////////////////////////////////////////////////////////////////////

/// The kind or length of the variably sized header Key
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VarKeyKind {
    /// A one byte key
    Key1,
    /// A two byte key
    Key2,
    /// A four byte key
    Key4,
    /// An eight byte key
    Key8,
}

//////////////////////////////////////////////////////////////////////////////
// VARSEQ
//////////////////////////////////////////////////////////////////////////////

/// A variably sized sequence number
///
/// NOTE: We use the standard PartialEq here, as we DO NOT treat sequence
/// numbers of different lengths as equivalent.
///
/// We DO NOT impl Serialize/Deserialize for this type because we use
/// non-postcard-compatible format (externally tagged)
#[derive(Debug, Clone, Copy)]
pub enum VarSeq {
    /// A one byte sequence number
    Seq1(u8),
    /// A two byte sequence number
    Seq2(u16),
    /// A four byte sequence number
    Seq4(u32),
}

impl From<u8> for VarSeq {
    fn from(value: u8) -> Self {
        Self::Seq1(value)
    }
}

impl From<u16> for VarSeq {
    fn from(value: u16) -> Self {
        Self::Seq2(value)
    }
}

impl From<u32> for VarSeq {
    fn from(value: u32) -> Self {
        Self::Seq4(value)
    }
}

impl Into<u8> for VarSeq {
    fn into(self) -> u8 {
        match self {
            VarSeq::Seq1(v) => v,
            VarSeq::Seq2(v) => v as u8,
            VarSeq::Seq4(v) => v as u8,
        }
    }
}

impl Into<u16> for VarSeq {
    fn into(self) -> u16 {
        match self {
            VarSeq::Seq1(v) => v.into(),
            VarSeq::Seq2(v) => v,
            VarSeq::Seq4(v) => v as u16,
        }
    }
}

impl Into<u32> for VarSeq {
    fn into(self) -> u32 {
        match self {
            VarSeq::Seq1(v) => v.into(),
            VarSeq::Seq2(v) => v.into(),
            VarSeq::Seq4(v) => v,
        }
    }
}

impl PartialEq for VarSeq {
    fn eq(&self, other: &Self) -> bool {
        Into::<u32>::into(*self) == Into::<u32>::into(*other)
    }
}

impl VarSeq {
    /// Resize (up or down) to the requested kind.
    ///
    /// When increasing size, the number is left-extended, e.g. `0x42u8` becomes
    /// `0x0000_0042u32` when resizing 1 -> 4.
    ///
    /// When decreasing size, the number is truncated, e.g. `0xABCD_EF12u32`
    /// becomes `0x12u8` when resizing 4 -> 1.
    pub fn resize(&mut self, kind: VarSeqKind) {
        match (&self, kind) {
            (VarSeq::Seq1(_), VarSeqKind::Seq1) => {}
            (VarSeq::Seq2(_), VarSeqKind::Seq2) => {}
            (VarSeq::Seq4(_), VarSeqKind::Seq4) => {}
            (VarSeq::Seq1(s), VarSeqKind::Seq2) => {
                *self = VarSeq::Seq2((*s).into());
            }
            (VarSeq::Seq1(s), VarSeqKind::Seq4) => {
                *self = VarSeq::Seq4((*s).into());
            }
            (VarSeq::Seq2(s), VarSeqKind::Seq1) => {
                *self = VarSeq::Seq1((*s) as u8);
            }
            (VarSeq::Seq2(s), VarSeqKind::Seq4) => {
                *self = VarSeq::Seq4((*s).into());
            }
            (VarSeq::Seq4(s), VarSeqKind::Seq1) => {
                *self = VarSeq::Seq1((*s) as u8);
            }
            (VarSeq::Seq4(s), VarSeqKind::Seq2) => {
                *self = VarSeq::Seq2((*s) as u16);
            }
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// VARSEQKIND
//////////////////////////////////////////////////////////////////////////////

/// The Kind or Length of a VarSeq
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VarSeqKind {
    /// A one byte sequence number
    Seq1,
    /// A two byte sequence number
    Seq2,
    /// A four byte sequence number
    Seq4,
}

//////////////////////////////////////////////////////////////////////////////
// VARHEADER
//////////////////////////////////////////////////////////////////////////////

/// A variably sized message header
///
/// NOTE: We use the standard PartialEq here as it will do the correct things.
///
/// Sequence numbers must be EXACTLY the same, and keys must be equivalent when
/// degraded to the smaller of the two.
///
/// We DO NOT impl Serialize/Deserialize for this type because we use
/// non-postcard-compatible format (externally tagged)
#[cfg_attr(not(feature = "use-std"), derive(Debug))]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Default)]
pub struct MacAddress {
    pub mac_address: [u8; 6],
}

impl MacAddress {
    pub fn broadcast() -> Self {
        Self {
            mac_address: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        }
    }
    // this is more of a 'marker address' rather than a real address
    pub fn localhost() -> Self {
        Self {
            mac_address: [127, 0, 0, 0, 0, 1],
        }
    }
}

impl Into<[u8; 6]> for MacAddress {
    fn into(self) -> [u8; 6] {
        self.mac_address
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(value: [u8; 6]) -> Self {
        Self { mac_address: value }
    }
}

impl From<&[u8; 6]> for MacAddress {
    fn from(value: &[u8; 6]) -> Self {
        Self {
            mac_address: value.clone(),
        }
    }
}

#[cfg(feature = "use-std")]
impl core::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.mac_address[0],
            self.mac_address[1],
            self.mac_address[2],
            self.mac_address[3],
            self.mac_address[4],
            self.mac_address[5]
        )
    }
}
/// Addressable meta trait just means an associated type is defined for the header.
/// This will be the 'address' type - which indicates where to send the message.
pub trait Addressable {
    type AddressType: PartialEq + Clone + Copy + Send + Default + core::fmt::Debug;
    fn with_addresses(&self, src: Self::AddressType, dst: Self::AddressType) -> Self;
    fn with_src(&self, src: Self::AddressType) -> Self;
    fn with_dst(&self, dst: Self::AddressType) -> Self;
    fn swap_addresses(&self) -> Self;
    // builds localhost/broadcast address types.
    fn localhost() -> Self::AddressType;
    fn broadcast() -> Self::AddressType;
}
pub trait HeaderImplMeta: Clone + Copy + Send + core::fmt::Debug {
    fn new(key: VarKey, seq_no: VarSeq) -> Self;
    fn key(&self) -> &VarKey;
    fn key_shrink_to(&self, kind: VarKeyKind) -> Self {
        let mut nk = self.key().clone();
        nk.shrink_to(kind);
        self.with_key(nk)
    }
    fn seq_no(&self) -> &VarSeq;
    fn with_key(&self, key: VarKey) -> Self;
    fn with_seq_no(&self, seq_no: VarSeq) -> Self;
}
// PartialEq is required to use in the WaitMap
pub trait Header: PartialEq + HeaderImplMeta + Addressable {
    fn into_response(&self, endpoint_response_key: VarKey) -> Self {
        self.with_key(endpoint_response_key).swap_addresses()
    }
    fn new_for_topic_broadcast(key: VarKey, seq_no: VarSeq) -> Self {
        Self::new(key, seq_no)
            .with_src(Self::localhost())
            .with_dst(Self::broadcast())
    }
    #[cfg(feature = "use-std")]
    fn write_to_vec(&self) -> Vec<u8>;
    fn write_to_slice<'a>(&self, buf: &'a mut [u8]) -> Option<(&'a mut [u8], &'a mut [u8])>;
    fn take_from_slice(buf: &[u8]) -> Option<(Self, &[u8])>
    where
        Self: Sized;
}

/// header
#[derive(Debug, Clone, Copy)]
pub struct VarHeader {
    /// The variably sized Key
    pub key: VarKey,
    /// The variably sized Sequence Number
    pub seq_no: VarSeq,
}

#[allow(clippy::unusual_byte_groupings)]
impl VarHeader {
    /// Bits for a key of ONE byte
    pub const KEY_ONE_BITS: u8 = 0b00_00_0000;
    /// Bits for a key of TWO bytes
    pub const KEY_TWO_BITS: u8 = 0b01_00_0000;
    /// Bits for a key of FOUR bytes
    pub const KEY_FOUR_BITS: u8 = 0b10_00_0000;
    /// Bits for a key of EIGHT bytes
    pub const KEY_EIGHT_BITS: u8 = 0b11_00_0000;
    /// Mask bits
    pub const KEY_MASK_BITS: u8 = 0b11_00_0000;

    /// Bits for a sequence number of ONE bytes
    pub const SEQ_ONE_BITS: u8 = 0b00_00_0000;
    /// Bits for a sequence number of TWO bytes
    pub const SEQ_TWO_BITS: u8 = 0b00_01_0000;
    /// Bits for a sequence number of FOUR bytes
    pub const SEQ_FOUR_BITS: u8 = 0b00_10_0000;
    /// Mask bits
    pub const SEQ_MASK_BITS: u8 = 0b00_11_0000;

    /// Bits for a version number of ZERO
    pub const VER_ZERO_BITS: u8 = 0b00_00_0000;
    /// Mask bits
    pub const VER_MASK_BITS: u8 = 0b00_00_1111;
}

impl HeaderImplMeta for VarHeader {
    fn new(key: VarKey, seq_no: VarSeq) -> Self {
        Self { key, seq_no }
    }

    fn key(&self) -> &VarKey {
        &self.key
    }

    fn seq_no(&self) -> &VarSeq {
        &self.seq_no
    }

    fn with_key(&self, key: VarKey) -> Self {
        Self {
            key,
            seq_no: self.seq_no,
        }
    }

    fn with_seq_no(&self, seq_no: VarSeq) -> Self {
        Self {
            key: self.key,
            seq_no,
        }
    }
}

impl Addressable for VarHeader {
    type AddressType = ();

    fn with_addresses(&self, _src: Self::AddressType, _dst: Self::AddressType) -> Self {
        self.clone()
    }

    fn with_src(&self, _src: Self::AddressType) -> Self {
        self.clone()
    }

    fn with_dst(&self, _dst: Self::AddressType) -> Self {
        self.clone()
    }

    fn swap_addresses(&self) -> Self {
        self.clone()
    }

    fn localhost() -> Self::AddressType {
        ()
    }

    fn broadcast() -> Self::AddressType {
        ()
    }
}

impl Header for VarHeader {
    /// Encode the header to a Vec of bytes
    #[cfg(feature = "use-std")]
    fn write_to_vec(&self) -> Vec<u8> {
        // start with placeholder byte
        let mut out = vec![0u8; 1];
        let mut disc_out: u8;
        match &self.key {
            VarKey::Key1(k) => {
                disc_out = Self::KEY_ONE_BITS;
                out.push(k.0);
            }
            VarKey::Key2(k) => {
                disc_out = Self::KEY_TWO_BITS;
                out.extend_from_slice(&k.0);
            }
            VarKey::Key4(k) => {
                disc_out = Self::KEY_FOUR_BITS;
                out.extend_from_slice(&k.0);
            }
            VarKey::Key8(k) => {
                disc_out = Self::KEY_EIGHT_BITS;
                out.extend_from_slice(&k.to_bytes());
            }
        }
        match &self.seq_no {
            VarSeq::Seq1(s) => {
                disc_out |= Self::SEQ_ONE_BITS;
                out.push(*s);
            }
            VarSeq::Seq2(s) => {
                disc_out |= Self::SEQ_TWO_BITS;
                out.extend_from_slice(&s.to_le_bytes());
            }
            VarSeq::Seq4(s) => {
                disc_out |= Self::SEQ_FOUR_BITS;
                out.extend_from_slice(&s.to_le_bytes());
            }
        }
        // push discriminant to the end...
        out.push(disc_out);
        // ...and swap-remove the placeholder byte, moving the discriminant to the front
        out.swap_remove(0);
        out
    }

    /// Attempt to write the header to the given slice
    ///
    /// If the slice is large enough, a `Some` will be returned with the bytes used
    /// to encode the header, as well as the remaining unused bytes.
    ///
    /// If the slice is not large enough, a `None` will be returned, and some bytes
    /// of the buffer may have been modified.
    fn write_to_slice<'a>(&self, buf: &'a mut [u8]) -> Option<(&'a mut [u8], &'a mut [u8])> {
        let (disc_out, mut remain) = buf.split_first_mut()?;
        let mut used = 1;

        match &self.key {
            VarKey::Key1(k) => {
                *disc_out = Self::KEY_ONE_BITS;
                let (keybs, remain2) = remain.split_first_mut()?;
                *keybs = k.0;
                remain = remain2;
                used += 1;
            }
            VarKey::Key2(k) => {
                *disc_out = Self::KEY_TWO_BITS;
                let (keybs, remain2) = remain.split_at_mut_checked(2)?;
                keybs.copy_from_slice(&k.0);
                remain = remain2;
                used += 2;
            }
            VarKey::Key4(k) => {
                *disc_out = Self::KEY_FOUR_BITS;
                let (keybs, remain2) = remain.split_at_mut_checked(4)?;
                keybs.copy_from_slice(&k.0);
                remain = remain2;
                used += 4;
            }
            VarKey::Key8(k) => {
                *disc_out = Self::KEY_EIGHT_BITS;
                let (keybs, remain2) = remain.split_at_mut_checked(8)?;
                keybs.copy_from_slice(&k.to_bytes());
                remain = remain2;
                used += 8;
            }
        }
        match &self.seq_no {
            VarSeq::Seq1(s) => {
                *disc_out |= Self::SEQ_ONE_BITS;
                let (seqbs, _) = remain.split_first_mut()?;
                *seqbs = *s;
                used += 1;
            }
            VarSeq::Seq2(s) => {
                *disc_out |= Self::SEQ_TWO_BITS;
                let (seqbs, _) = remain.split_at_mut_checked(2)?;
                seqbs.copy_from_slice(&s.to_le_bytes());
                used += 2;
            }
            VarSeq::Seq4(s) => {
                *disc_out |= Self::SEQ_FOUR_BITS;
                let (seqbs, _) = remain.split_at_mut_checked(4)?;
                seqbs.copy_from_slice(&s.to_le_bytes());
                used += 4;
            }
        }
        Some(buf.split_at_mut(used))
    }

    /// Attempt to decode a header from the given bytes.
    ///
    /// If a well-formed header was found, a `Some` will be returned with the
    /// decoded header and unused remaining bytes.
    ///
    /// If no well-formed header was found, a `None` will be returned.
    fn take_from_slice(buf: &[u8]) -> Option<(Self, &[u8])> {
        let (disc, mut remain) = buf.split_first()?;

        // For now, we only trust version zero
        if (*disc & Self::VER_MASK_BITS) != Self::VER_ZERO_BITS {
            return None;
        }

        let key = match (*disc) & Self::KEY_MASK_BITS {
            Self::KEY_ONE_BITS => {
                let (keybs, remain2) = remain.split_first()?;
                remain = remain2;
                VarKey::Key1(Key1(*keybs))
            }
            Self::KEY_TWO_BITS => {
                let (keybs, remain2) = remain.split_at_checked(2)?;
                remain = remain2;
                let mut buf = [0u8; 2];
                buf.copy_from_slice(keybs);
                VarKey::Key2(Key2(buf))
            }
            Self::KEY_FOUR_BITS => {
                let (keybs, remain2) = remain.split_at_checked(4)?;
                remain = remain2;
                let mut buf = [0u8; 4];
                buf.copy_from_slice(keybs);
                VarKey::Key4(Key4(buf))
            }
            Self::KEY_EIGHT_BITS => {
                let (keybs, remain2) = remain.split_at_checked(8)?;
                remain = remain2;
                let mut buf = [0u8; 8];
                buf.copy_from_slice(keybs);
                VarKey::Key8(unsafe { Key::from_bytes(buf) })
            }
            // Impossible: all bits covered
            _ => unreachable!(),
        };
        let seq_no = match (*disc) & Self::SEQ_MASK_BITS {
            Self::SEQ_ONE_BITS => {
                let (seqbs, remain3) = remain.split_first()?;
                remain = remain3;
                VarSeq::Seq1(*seqbs)
            }
            Self::SEQ_TWO_BITS => {
                let (seqbs, remain3) = remain.split_at_checked(2)?;
                remain = remain3;
                let mut buf = [0u8; 2];
                buf.copy_from_slice(seqbs);
                VarSeq::Seq2(u16::from_le_bytes(buf))
            }
            Self::SEQ_FOUR_BITS => {
                let (seqbs, remain3) = remain.split_at_checked(4)?;
                remain = remain3;
                let mut buf = [0u8; 4];
                buf.copy_from_slice(seqbs);
                VarSeq::Seq4(u32::from_le_bytes(buf))
            }
            // Possible (could be 0b11), is invalid
            _ => return None,
        };
        Some((Self { key, seq_no }, remain))
    }
}

pub type UnicastHeader = VarHeader;

impl PartialEq for UnicastHeader {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.seq_no == other.seq_no
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BroadcastHeader {
    pub vh: VarHeader,
    pub src: MacAddress,
    pub dst: MacAddress,
}

impl Addressable for BroadcastHeader {
    type AddressType = MacAddress;

    fn with_addresses(&self, src: Self::AddressType, dst: Self::AddressType) -> Self {
        Self {
            vh: self.vh,
            src,
            dst,
        }
    }

    fn with_src(&self, src: Self::AddressType) -> Self {
        Self {
            vh: self.vh,
            src,
            dst: self.dst,
        }
    }

    fn with_dst(&self, dst: Self::AddressType) -> Self {
        Self {
            vh: self.vh,
            src: self.src,
            dst,
        }
    }

    fn swap_addresses(&self) -> Self {
        Self {
            vh: self.vh,
            src: self.dst,
            dst: self.src,
        }
    }

    fn localhost() -> Self::AddressType {
        MacAddress::localhost()
    }

    fn broadcast() -> Self::AddressType {
        MacAddress::broadcast()
    }
}

impl Header for BroadcastHeader {
    #[cfg(feature = "use-std")]
    fn write_to_vec(&self) -> Vec<u8> {
        let mut vhvec = self.vh.write_to_vec();
        vhvec.append(&mut self.src.mac_address.to_vec());
        vhvec.append(&mut self.dst.mac_address.to_vec());
        vhvec
    }

    fn write_to_slice<'a>(&self, buf: &'a mut [u8]) -> Option<(&'a mut [u8], &'a mut [u8])> {
        let ab = self.vh.write_to_slice(buf);
        let (a, b) = ab?;
        if b.len() < 12 {
            return None;
        }
        // split for the src address, then the dst address
        let (src, rest) = b.split_at_mut(6);
        src.copy_from_slice(&self.src.mac_address);
        let (dst, rest2) = rest.split_at_mut(6);
        dst.copy_from_slice(&self.dst.mac_address);
        // return the remaining slice
        Some((a, rest2))
    }

    fn take_from_slice(buf: &[u8]) -> Option<(Self, &[u8])> {
        if let Some((vh, rest)) = VarHeader::take_from_slice(buf) {
            // split for the src address, then the dst address
            let (src, rest) = rest.split_at(6);
            let src: [u8; 6] = src.try_into().unwrap();
            let src_addr: MacAddress = src.into();
            let (dst, rest) = rest.split_at(6);
            let dst: [u8; 6] = dst.try_into().unwrap();
            let dst_addr: MacAddress = dst.into();

            Some((
                Self {
                    vh,
                    src: src_addr,
                    dst: dst_addr,
                },
                rest,
            ))
        } else {
            None
        }
    }
}

impl HeaderImplMeta for BroadcastHeader {
    fn new(key: VarKey, seq_no: VarSeq) -> Self {
        Self {
            vh: VarHeader::new(key, seq_no),
            src: MacAddress::default(),
            dst: MacAddress::default(),
        }
    }

    fn key(&self) -> &VarKey {
        self.vh.key()
    }

    fn seq_no(&self) -> &VarSeq {
        self.vh.seq_no()
    }

    fn with_key(&self, key: VarKey) -> Self {
        Self {
            vh: self.vh.with_key(key),
            src: self.src,
            dst: self.dst,
        }
    }

    fn with_seq_no(&self, seq_no: VarSeq) -> Self {
        Self {
            vh: self.vh.with_seq_no(seq_no),
            src: self.src,
            dst: self.dst,
        }
    }
}

impl PartialEq for BroadcastHeader {
    fn eq(&self, other: &Self) -> bool {
        // this one is a bit conditional! as it handles the case where we sent a broadcast and
        // are expecting a reply - but we dont know where it will come from.
        if self.src == Self::broadcast() {
            self.vh == other.vh && self.dst == other.dst
        } else {
            self.vh == other.vh && self.src == other.src && self.dst == other.dst
        }
    }
}

/// A marker trait for initializing drivers in a specific mode.
/// Inspired by https://github.com/esp-rs/esp-hal
pub trait HeaderMode: Clone + 'static {
    type HeaderType: Header; // the HeaderType must be something that impliments HeaderImpl / VarFields
}
#[derive(Debug, Copy, Clone)]
pub struct Unicast; // point-to-point, non-addressed communications channel. server+client

#[derive(Debug, Copy, Clone)]
pub struct Broadcast(PhantomData<fn() -> *const ()>);
// pub struct Wireless(PhantomData<fn(*const ()) -> *const ()>);
// pub struct Wireless(PhantomData<fn(*const ())>);
// pub struct Wireless(PhantomData<fn() -> *const ()>);
// point-to-multi-point, addressed + routed communications channel. servers+clients.
// doing PhantomData<fn() -> *const ()> allows Wireless to be Send! :O
// https://doc.rust-lang.org/nomicon/phantom-data.html#table-of-phantomdata-patterns

impl HeaderMode for Unicast {
    type HeaderType = UnicastHeader;
}
impl HeaderMode for Broadcast {
    type HeaderType = BroadcastHeader;
}

// Requires adding 'trait-impl-incorrect-safety' to 'rust-analyzer.diagnostics.disabled'
unsafe impl Send for Unicast {}
unsafe impl Send for Broadcast {}

#[cfg(test)]
mod test {
    use super::{Addressable, BroadcastHeader, Header, HeaderImplMeta, HeaderMode};
    use super::{Broadcast, Unicast, VarHeader, VarKey, VarSeq};
    use crate::{Key, Key1, Key2};

    #[test]
    fn wire_format() {
        let checks: &[(_, &[u8])] = &[
            (
                VarHeader {
                    key: VarKey::Key1(Key1(0)),
                    seq_no: VarSeq::Seq1(0x00),
                },
                &[
                    VarHeader::KEY_ONE_BITS | VarHeader::SEQ_ONE_BITS,
                    0x00,
                    0x00,
                ],
            ),
            (
                VarHeader {
                    key: VarKey::Key1(Key1(1)),
                    seq_no: VarSeq::Seq1(0x02),
                },
                &[
                    VarHeader::KEY_ONE_BITS | VarHeader::SEQ_ONE_BITS,
                    0x01,
                    0x02,
                ],
            ),
            (
                VarHeader {
                    key: VarKey::Key2(Key2([0x42, 0xAF])),
                    seq_no: VarSeq::Seq1(0x02),
                },
                &[
                    VarHeader::KEY_TWO_BITS | VarHeader::SEQ_ONE_BITS,
                    0x42,
                    0xAF,
                    0x02,
                ],
            ),
            (
                VarHeader {
                    key: VarKey::Key1(Key1(1)),
                    seq_no: VarSeq::Seq2(0x42_AF),
                },
                &[
                    VarHeader::KEY_ONE_BITS | VarHeader::SEQ_TWO_BITS,
                    0x01,
                    0xAF,
                    0x42,
                ],
            ),
            (
                VarHeader {
                    key: VarKey::Key8(unsafe {
                        Key::from_bytes([0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89])
                    }),
                    seq_no: VarSeq::Seq4(0x42_AF_AA_BB),
                },
                &[
                    VarHeader::KEY_EIGHT_BITS | VarHeader::SEQ_FOUR_BITS,
                    0x12,
                    0x23,
                    0x34,
                    0x45,
                    0x56,
                    0x67,
                    0x78,
                    0x89,
                    0xBB,
                    0xAA,
                    0xAF,
                    0x42,
                ],
            ),
        ];

        let mut buf = [0u8; 1 + 8 + 4];

        for (val, exp) in checks.iter() {
            let (used, _) = val.write_to_slice(&mut buf).unwrap();
            assert_eq!(used, *exp);
            let v = val.write_to_vec();
            assert_eq!(&v, *exp);
            let (deser, remain) = VarHeader::take_from_slice(used).unwrap();
            assert!(remain.is_empty());
            assert_eq!(val, &deser);
        }
    }

    #[test]
    fn var_seq_equality() {
        let val32 = 0x12345678;
        let val16 = 0x9abc;
        let val8 = 0xde;

        assert_eq!(VarSeq::Seq1(val8), VarSeq::Seq1(val8));
        assert_eq!(VarSeq::Seq1(val8), VarSeq::Seq2(val8.into()));
        assert_eq!(VarSeq::Seq1(val8), VarSeq::Seq4(val8.into()));
        assert_ne!(VarSeq::Seq2(val16), VarSeq::Seq1(val16 as u8));
        assert_eq!(VarSeq::Seq2(val16), VarSeq::Seq2(val16));
        assert_eq!(VarSeq::Seq2(val16), VarSeq::Seq4(val16.into()));
        assert_ne!(VarSeq::Seq4(val32), VarSeq::Seq1(val32 as u8));
        assert_ne!(VarSeq::Seq4(val32), VarSeq::Seq2(val32 as u16));
        assert_eq!(VarSeq::Seq4(val32), VarSeq::Seq4(val32));
    }

    // Test serialization and deserialization of Unicast and Broadcast headers
    fn build_header<M: HeaderMode>() -> M::HeaderType {
        let k = VarKey::Key1(Key1(0x69));
        let s = VarSeq::Seq2(0x1234);
        M::HeaderType::new(k, s)
    }

    // Generic function for testing serde of headers
    fn test_header_serde<H: Header>(header: H) -> H {
        let header_bytes = header.write_to_vec();
        let (deserialized_header, _) = H::take_from_slice(&header_bytes).unwrap();
        assert_eq!(header, deserialized_header);
        deserialized_header
    }

    #[test]
    fn unicast_serde() {
        let header = build_header::<Unicast>();
        println!("{:?}", header);
        test_header_serde(header);
    }

    #[test]
    fn broadcast_serde() {
        let header = build_header::<Broadcast>();
        println!("{:?}", header);
        test_header_serde(header);
    }

    #[test]
    fn broadcast_serde_addresses() {
        let mut header = build_header::<Broadcast>();
        header = header.with_src(<BroadcastHeader as Addressable>::AddressType::localhost());
        header = header.with_dst(<BroadcastHeader as Addressable>::AddressType::broadcast());
        println!("{:?}", header);
        let received = test_header_serde(header);
        println!("{:?}", received);
    }
}
