//! Opaque identifiers for folders and entries.
//!
//! Random 128-bit ids rather than sequential ones. A sequential id would leak ordering
//! and count to a store reader beyond what the metadata already gives away; a random id
//! adds nothing an observer can correlate. They are generated once, at creation, and
//! referenced by later events.

use serde::{Deserialize, Serialize};

/// Length of an id in bytes.
pub const ID_LEN: usize = 16;

macro_rules! define_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub [u8; ID_LEN]);

        impl $name {
            /// Generates a fresh random id.
            ///
            /// # Errors
            ///
            /// [`Error::Malformed`] if the OS random source is unavailable - fatal, and a
            /// caller should not invent an id from weaker randomness.
            ///
            /// [`Error::Malformed`]: crate::Error::Malformed
            pub fn generate() -> crate::Result<Self> {
                let mut bytes = [0u8; ID_LEN];
                getrandom::fill(&mut bytes)
                    .map_err(|_| crate::Error::Malformed("OS random source unavailable"))?;
                Ok(Self(bytes))
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Short prefix - full ids make debug output unreadable.
                let prefix = self.0.get(..4).unwrap_or(&self.0);
                write!(f, "{}({})", stringify!($name), hex::encode(prefix))
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }
    };
}

define_id!(FolderId, "Opaque identifier for a folder.");
define_id!(EntryId, "Opaque identifier for a connection entry.");
define_id!(CredentialId, "Opaque identifier for a vault credential.");
