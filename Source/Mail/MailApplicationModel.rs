// SPDX-License-Identifier: MIT
// Native Mail exchanges bounded presentation data without exposing vault keys.
use super::*;
use zeroize::Zeroize;

#[derive(Clone, Default)]
pub(crate) struct Overview {
    pub mailboxes: Vec<MailboxInfo>,
    pub contacts: Vec<ContactInfo>,
    pub outbox: Vec<OutgoingInfo>,
    pub archive: Vec<MessageInfo>,
    pub stores: Vec<String>,
}
#[derive(Clone)]
pub(crate) struct MailboxInfo {
    pub label: String,
    pub address: String,
    pub private: bool,
    pub stores: Vec<String>,
}
#[derive(Clone)]
pub(crate) struct ContactInfo {
    pub address: String,
    pub owner: String,
    pub generation: u64,
}
#[derive(Clone)]
pub(crate) struct OutgoingInfo {
    pub message: String,
    pub mailbox: String,
    pub recipient: String,
    pub subject: String,
    pub state: &'static str,
    pub copies: usize,
    pub required_copies: Option<u16>,
}
impl Drop for OutgoingInfo {
    fn drop(&mut self) {
        self.subject.zeroize();
    }
}
#[derive(Clone)]
pub(crate) struct MessageInfo {
    pub id: String,
    pub mailbox: String,
    pub subject: Option<String>,
    pub sender: Option<String>,
    pub bytes: Option<u64>,
    pub expires: u64,
}
impl Drop for MessageInfo {
    fn drop(&mut self) {
        if let Some(subject) = &mut self.subject {
            subject.zeroize();
        }
    }
}
pub(crate) struct Inbox {
    pub messages: Vec<MessageInfo>,
    pub next: Option<String>,
}
#[derive(Clone)]
pub(crate) struct Draft {
    pub recipient: String,
    pub subject: String,
    pub body: String,
    pub retention_hours: u32,
}
impl Default for Draft {
    fn default() -> Self {
        Self {
            recipient: String::new(),
            subject: String::new(),
            body: String::new(),
            retention_hours: 24,
        }
    }
}
impl Drop for Draft {
    fn drop(&mut self) {
        self.subject.zeroize();
        self.body.zeroize();
    }
}
#[derive(Clone)]
pub(crate) struct Review {
    pub mailbox: String,
    pub message: String,
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub body: String,
    pub expires: u64,
    pub consent: application_consent::SendConsent,
}
impl Drop for Review {
    fn drop(&mut self) {
        self.subject.zeroize();
        self.body.zeroize();
    }
}
#[derive(Clone)]
pub(crate) enum Request {
    Refresh,
    Inbox {
        mailbox: String,
        store: String,
        after: Option<String>,
    },
    Read {
        mailbox: String,
        store: String,
        message: String,
    },
    ArchiveRead {
        message: String,
    },
    ArchiveDelete {
        message: String,
    },
    RemoteDelete {
        mailbox: String,
        store: String,
        message: String,
    },
    Compose {
        mailbox: String,
        draft: Draft,
    },
    Review {
        message: String,
        store: String,
    },
    Send {
        review: Box<Review>,
    },
    VerifyContact {
        mailbox: String,
        address: String,
        owner: String,
    },
    Refill {
        mailbox: String,
    },
}
pub(crate) enum Detail {
    None,
    Inbox(Inbox),
    Letter(Box<crypto::Letter>),
    Composed(String),
    Review(Box<Review>),
}
pub(crate) struct Response {
    pub overview: Overview,
    pub detail: Detail,
    pub status: String,
}
