// lsm-sgx/src/types.rs
//
// Core types for the LSM-tree, inspired by Fjall's internal key design.
//
// Every KV pair in the LSM-tree is wrapped in an InternalKey which adds:
// - A sequence number (monotonic timestamp) for MVCC
// - A value type (Put or Delete) to support tombstones
//
// Sorting: (user_key ASC, seqno DESC)
// This means for the same user_key, the newest version comes first,
// so point reads can stop at the first match.

use core::cmp::Ordering;

/// Monotonically increasing sequence number.
/// Each write operation (or batch) gets a unique seqno.
/// Higher seqno = more recent.
pub type SeqNo = u64;

/// Distinguishes insertions from deletions (tombstones).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ValueType {
    /// A regular key-value insertion
    Put = 0,

    /// A deletion marker (tombstone)
    /// The value field is empty for tombstones.
    Delete = 1,
}

impl ValueType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ValueType::Put),
            1 => Some(ValueType::Delete),
            _ => None,
        }
    }
}

/// A user-provided key. Just raw bytes — the LSM-tree is agnostic
/// about key structure.
///
/// In std mode this is Vec<u8>, in no_std mode it could be adapted.
#[cfg(feature = "std")]
pub type UserKey = Vec<u8>;

#[cfg(not(feature = "std"))]
pub type UserKey = alloc::vec::Vec<u8>;

/// A user-provided value. Also just raw bytes.
#[cfg(feature = "std")]
pub type UserValue = Vec<u8>;

#[cfg(not(feature = "std"))]
pub type UserValue = alloc::vec::Vec<u8>;

/// The internal key used throughout the LSM-tree.
///
/// This wraps the user's key with metadata needed for MVCC and
/// tombstone support. Every entry in the memtable and every entry
/// serialized into an SSTable uses this representation.
///
/// Ordering: sorted by (user_key ASC, seqno DESC).
/// The descending seqno means the newest version of any key comes
/// first when iterating. This is the same trick Fjall and LevelDB use.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InternalKey {
    /// The actual key the user provided
    pub user_key: UserKey,

    /// Sequence number — monotonically increasing timestamp
    pub seqno: SeqNo,

    /// Whether this is an insertion or deletion
    pub value_type: ValueType,
}

impl InternalKey {
    /// Create a new internal key for a Put operation.
    pub fn new(user_key: impl Into<UserKey>, seqno: SeqNo, value_type: ValueType) -> Self {
        Self {
            user_key: user_key.into(),
            seqno,
            value_type,
        }
    }

    /// Convenience: create a Put key
    pub fn put(user_key: impl Into<UserKey>, seqno: SeqNo) -> Self {
        Self::new(user_key, seqno, ValueType::Put)
    }

    /// Convenience: create a Delete (tombstone) key
    pub fn delete(user_key: impl Into<UserKey>, seqno: SeqNo) -> Self {
        Self::new(user_key, seqno, ValueType::Delete)
    }

    /// Returns the encoded size in bytes when serialized.
    ///
    /// Wire format:
    ///   [key_len: u16][user_key: key_len bytes][seqno: u64][value_type: u8]
    pub fn encoded_size(&self) -> usize {
        2 + self.user_key.len() + 8 + 1
    }

    /// Encode this internal key into a byte buffer.
    ///
    /// Format:
    ///   [key_len: u16 BE][user_key bytes][seqno: u64 BE][value_type: u8]
    ///
    /// Big-endian is used so that byte-wise comparison preserves ordering
    /// for the key_len and seqno fields.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let key_len = self.user_key.len() as u16;
        buf.extend_from_slice(&key_len.to_be_bytes());
        buf.extend_from_slice(&self.user_key);
        buf.extend_from_slice(&self.seqno.to_be_bytes());
        buf.push(self.value_type as u8);
    }

    /// Decode an internal key from a byte slice.
    /// Returns the key and the number of bytes consumed.
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }

        let key_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let total = 2 + key_len + 8 + 1;

        if data.len() < total {
            return None;
        }

        let user_key = data[2..2 + key_len].to_vec();
        let seqno_start = 2 + key_len;
        let seqno = u64::from_be_bytes([
            data[seqno_start],
            data[seqno_start + 1],
            data[seqno_start + 2],
            data[seqno_start + 3],
            data[seqno_start + 4],
            data[seqno_start + 5],
            data[seqno_start + 6],
            data[seqno_start + 7],
        ]);
        let value_type = ValueType::from_u8(data[seqno_start + 8])?;

        Some((
            InternalKey {
                user_key,
                seqno,
                value_type,
            },
            total,
        ))
    }
}

/// Ordering: (user_key ASC, seqno DESC)
///
/// This is Fjall's elegant trick using Reverse(seqno):
///   (&self.user_key, Reverse(self.seqno)).cmp(...)
///
/// For the same user_key, higher seqno (newer) sorts FIRST.
/// This means when scanning forward, you always hit the newest
/// version of a key before older versions.
impl Ord for InternalKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.user_key
            .cmp(&other.user_key)
            .then_with(|| other.seqno.cmp(&self.seqno)) // Note: reversed!
    }
}

impl PartialOrd for InternalKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A complete internal entry: the internal key plus its value.
///
/// This is what gets stored in the memtable and serialized into
/// SSTable blocks.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InternalEntry {
    pub key: InternalKey,
    pub value: UserValue,
}

impl InternalEntry {
    pub fn new(key: InternalKey, value: impl Into<UserValue>) -> Self {
        Self {
            key,
            value: value.into(),
        }
    }

    /// Create a Put entry
    pub fn put(user_key: impl Into<UserKey>, seqno: SeqNo, value: impl Into<UserValue>) -> Self {
        Self::new(InternalKey::put(user_key, seqno), value)
    }

    /// Create a Delete (tombstone) entry
    pub fn delete(user_key: impl Into<UserKey>, seqno: SeqNo) -> Self {
        Self::new(InternalKey::delete(user_key, seqno), Vec::new())
    }

    /// Returns the encoded size in bytes.
    ///
    /// Wire format:
    ///   [internal_key bytes][value_len: u32 BE][value bytes]
    pub fn encoded_size(&self) -> usize {
        self.key.encoded_size() + 4 + self.value.len()
    }

    /// Encode this entry into a byte buffer.
    ///
    /// Format:
    ///   [key_len: u16 BE][user_key][seqno: u64 BE][value_type: u8][value_len: u32 BE][value]
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.key.encode(buf);
        let val_len = self.value.len() as u32;
        buf.extend_from_slice(&val_len.to_be_bytes());
        buf.extend_from_slice(&self.value);
    }

    /// Decode an entry from a byte slice.
    /// Returns the entry and bytes consumed.
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let (key, key_bytes) = InternalKey::decode(data)?;

        let rest = &data[key_bytes..];
        if rest.len() < 4 {
            return None;
        }

        let val_len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;

        if rest.len() < 4 + val_len {
            return None;
        }

        let value = rest[4..4 + val_len].to_vec();
        let total = key_bytes + 4 + val_len;

        Some((InternalEntry { key, value }, total))
    }
}

impl Ord for InternalEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for InternalEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_type_roundtrip() {
        assert_eq!(ValueType::from_u8(0), Some(ValueType::Put));
        assert_eq!(ValueType::from_u8(1), Some(ValueType::Delete));
        assert_eq!(ValueType::from_u8(2), None);
    }

    #[test]
    fn test_internal_key_ordering() {
        // Same user_key, different seqno: higher seqno sorts FIRST
        let k1 = InternalKey::put(b"hello".to_vec(), 5);
        let k2 = InternalKey::put(b"hello".to_vec(), 10);
        assert!(k2 < k1, "higher seqno should sort before lower seqno");

        // Different user_keys: lexicographic order
        let ka = InternalKey::put(b"aaa".to_vec(), 1);
        let kb = InternalKey::put(b"bbb".to_vec(), 1);
        assert!(ka < kb);

        // user_key ordering takes priority over seqno
        let ka_old = InternalKey::put(b"aaa".to_vec(), 1);
        let kb_new = InternalKey::put(b"bbb".to_vec(), 100);
        assert!(ka_old < kb_new);
    }

    #[test]
    fn test_internal_key_ordering_same_key_descending_seqno() {
        // Simulate what you'd see in a memtable for key "user1":
        //   user1:seqno=10  (newest, should be first)
        //   user1:seqno=5
        //   user1:seqno=1   (oldest, should be last)
        let mut keys = vec![
            InternalKey::put(b"user1".to_vec(), 1),
            InternalKey::put(b"user1".to_vec(), 10),
            InternalKey::put(b"user1".to_vec(), 5),
        ];
        keys.sort();

        assert_eq!(keys[0].seqno, 10);
        assert_eq!(keys[1].seqno, 5);
        assert_eq!(keys[2].seqno, 1);
    }

    #[test]
    fn test_internal_key_encode_decode_roundtrip() {
        let key = InternalKey::put(b"test_key".to_vec(), 42);
        let mut buf = Vec::new();
        key.encode(&mut buf);

        let (decoded, consumed) = InternalKey::decode(&buf).unwrap();
        assert_eq!(decoded, key);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_internal_entry_encode_decode_roundtrip() {
        let entry = InternalEntry::put(
            b"my_key".to_vec(),
            100,
            b"hello world".to_vec(),
        );
        let mut buf = Vec::new();
        entry.encode(&mut buf);

        let (decoded, consumed) = InternalEntry::decode(&buf).unwrap();
        assert_eq!(decoded.key, entry.key);
        assert_eq!(decoded.value, entry.value);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_tombstone_entry() {
        let entry = InternalEntry::delete(b"dead_key".to_vec(), 50);
        assert_eq!(entry.key.value_type, ValueType::Delete);
        assert!(entry.value.is_empty());

        let mut buf = Vec::new();
        entry.encode(&mut buf);

        let (decoded, _) = InternalEntry::decode(&buf).unwrap();
        assert_eq!(decoded.key.value_type, ValueType::Delete);
        assert!(decoded.value.is_empty());
    }

    #[test]
    fn test_encoded_size_matches_actual() {
        let entry = InternalEntry::put(
            b"key123".to_vec(),
            999,
            b"value_data".to_vec(),
        );
        let mut buf = Vec::new();
        entry.encode(&mut buf);
        assert_eq!(buf.len(), entry.encoded_size());
    }

    #[test]
    fn test_multiple_entries_sequential_decode() {
        let entries = vec![
            InternalEntry::put(b"aaa".to_vec(), 3, b"val_a".to_vec()),
            InternalEntry::put(b"bbb".to_vec(), 2, b"val_b".to_vec()),
            InternalEntry::delete(b"ccc".to_vec(), 1),
        ];

        let mut buf = Vec::new();
        for e in &entries {
            e.encode(&mut buf);
        }

        // Decode them back sequentially
        let mut offset = 0;
        for expected in &entries {
            let (decoded, consumed) = InternalEntry::decode(&buf[offset..]).unwrap();
            assert_eq!(&decoded.key, &expected.key);
            assert_eq!(&decoded.value, &expected.value);
            offset += consumed;
        }
        assert_eq!(offset, buf.len());
    }
}
