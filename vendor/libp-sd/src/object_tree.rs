// Object-type tree encoding for AccessCheck.
//
// A KACS object-type tree is a flat, depth-ordered array of 20-byte
// entries. Each node carries a `level` (depth, 0 = root) and a 16-byte
// type GUID; the tree structure is implied by the level sequence.

use alloc::vec::Vec;
use crate::abi::KacsObjectTypeEntry;

/// One node in an object-type tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectTypeNode {
    /// Depth in the tree. The root is level 0; children are 1, etc.
    pub level: u16,
    /// 16-byte object-type GUID.
    pub guid: [u8; 16],
}

impl ObjectTypeNode {
    /// A node at the given depth with the given GUID.
    pub fn new(level: u16, guid: [u8; 16]) -> Self {
        ObjectTypeNode { level, guid }
    }

    /// A root node (level 0).
    pub fn root(guid: [u8; 16]) -> Self {
        ObjectTypeNode { level: 0, guid }
    }
}

/// Encode a slice of object-type nodes into the flat 20-byte-per-entry
/// wire array. An empty slice produces an empty `Vec`.
pub fn encode_object_tree(nodes: &[ObjectTypeNode]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * core::mem::size_of::<KacsObjectTypeEntry>());
    for n in nodes {
        out.extend_from_slice(&n.level.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // _reserved
        out.extend_from_slice(&n.guid);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn empty_tree_is_empty() {
        assert!(encode_object_tree(&[]).is_empty());
    }

    #[test]
    fn each_node_is_20_bytes() {
        let nodes = vec![
            ObjectTypeNode::root([1u8; 16]),
            ObjectTypeNode::new(1, [2u8; 16]),
        ];
        let bytes = encode_object_tree(&nodes);
        assert_eq!(bytes.len(), 40);
        // First node: level 0.
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0);
        // _reserved must be zero.
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0);
        assert_eq!(&bytes[4..20], &[1u8; 16]);
        // Second node: level 1.
        assert_eq!(u16::from_le_bytes([bytes[20], bytes[21]]), 1);
    }
}
