use rusqlite::{params, Connection, OptionalExtension};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub type StorageResult<T> = Result<T, rusqlite::Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageDirection {
    Sent,
    Received,
}

impl MessageDirection {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "received" => Self::Received,
            _ => Self::Sent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageStatus {
    Stored,
    Sent,
    Received,
}

impl MessageStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "sent" => Self::Sent,
            "received" => Self::Received,
            _ => Self::Stored,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxStatus {
    Pending,
    Delivered,
}

impl OutboxStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "delivered" => Self::Delivered,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRecord {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub direction: MessageDirection,
    pub status: MessageStatus,
    pub protocol_counter: Option<u64>,
    pub ciphertext: Vec<u8>,
    pub plaintext: Option<String>,
    pub created_at_unix_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    pub message_id: String,
    pub recipient_id: String,
    pub payload: Vec<u8>,
    pub status: OutboxStatus,
    pub retry_count: u64,
    pub created_at_unix_secs: u64,
    pub last_attempt_unix_secs: Option<u64>,
}

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let conn = Connection::open(path)?;
        let storage = Self { conn };
        storage.init()?;
        Ok(storage)
    }

    pub fn open_in_memory() -> StorageResult<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn };
        storage.init()?;
        Ok(storage)
    }

    fn init(&self) -> StorageResult<()> {
        self.conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS local_identity (
                id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                state BLOB NOT NULL,
                updated_at_unix_secs INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                conversation_id TEXT PRIMARY KEY,
                peer_id TEXT NOT NULL,
                role TEXT NOT NULL,
                state BLOB NOT NULL,
                updated_at_unix_secs INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                status TEXT NOT NULL,
                protocol_counter INTEGER,
                ciphertext BLOB NOT NULL,
                plaintext TEXT,
                created_at_unix_secs INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbox (
                message_id TEXT PRIMARY KEY,
                recipient_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                status TEXT NOT NULL,
                retry_count INTEGER NOT NULL,
                created_at_unix_secs INTEGER NOT NULL,
                last_attempt_unix_secs INTEGER
            );

            CREATE TABLE IF NOT EXISTS accepted_messages (
                message_id TEXT PRIMARY KEY,
                accepted_at_unix_secs INTEGER NOT NULL
            );
            ",
        )
    }

    pub fn save_local_identity(&self, id: &str, role: &str, state: &[u8]) -> StorageResult<()> {
        self.conn.execute(
            "
            INSERT INTO local_identity (id, role, state, updated_at_unix_secs)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(id) DO UPDATE SET
                role = excluded.role,
                state = excluded.state,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![id, role, state, now_unix_secs() as i64],
        )?;
        Ok(())
    }

    pub fn load_local_identity(&self, id: &str) -> StorageResult<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT state FROM local_identity WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn save_session(
        &self,
        conversation_id: &str,
        peer_id: &str,
        role: &str,
        state: &[u8],
    ) -> StorageResult<()> {
        self.conn.execute(
            "
            INSERT INTO sessions (conversation_id, peer_id, role, state, updated_at_unix_secs)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(conversation_id) DO UPDATE SET
                peer_id = excluded.peer_id,
                role = excluded.role,
                state = excluded.state,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![
                conversation_id,
                peer_id,
                role,
                state,
                now_unix_secs() as i64
            ],
        )?;
        Ok(())
    }

    pub fn load_session(&self, conversation_id: &str) -> StorageResult<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT state FROM sessions WHERE conversation_id = ?1",
                params![conversation_id],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn insert_message(&self, message: &MessageRecord) -> StorageResult<()> {
        self.conn.execute(
            "
            INSERT OR IGNORE INTO messages (
                message_id,
                conversation_id,
                sender_id,
                recipient_id,
                direction,
                status,
                protocol_counter,
                ciphertext,
                plaintext,
                created_at_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ",
            params![
                &message.message_id,
                &message.conversation_id,
                &message.sender_id,
                &message.recipient_id,
                message.direction.as_str(),
                message.status.as_str(),
                message.protocol_counter.map(|value| value as i64),
                &message.ciphertext,
                &message.plaintext,
                message.created_at_unix_secs as i64,
            ],
        )?;
        Ok(())
    }

    pub fn save_state_session_and_insert_message(
        &mut self,
        local_identity_id: &str,
        local_identity_role: &str,
        local_identity_state: &[u8],
        conversation_id: &str,
        peer_id: &str,
        session_role: &str,
        session_state: &[u8],
        message: &MessageRecord,
    ) -> StorageResult<()> {
        let tx = self.conn.transaction()?;
        let now = now_unix_secs() as i64;

        tx.execute(
            "
            INSERT INTO local_identity (id, role, state, updated_at_unix_secs)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(id) DO UPDATE SET
                role = excluded.role,
                state = excluded.state,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![
                local_identity_id,
                local_identity_role,
                local_identity_state,
                now
            ],
        )?;
        tx.execute(
            "
            INSERT INTO sessions (conversation_id, peer_id, role, state, updated_at_unix_secs)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(conversation_id) DO UPDATE SET
                peer_id = excluded.peer_id,
                role = excluded.role,
                state = excluded.state,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![conversation_id, peer_id, session_role, session_state, now],
        )?;
        tx.execute(
            "
            INSERT OR IGNORE INTO messages (
                message_id,
                conversation_id,
                sender_id,
                recipient_id,
                direction,
                status,
                protocol_counter,
                ciphertext,
                plaintext,
                created_at_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ",
            params![
                &message.message_id,
                &message.conversation_id,
                &message.sender_id,
                &message.recipient_id,
                message.direction.as_str(),
                message.status.as_str(),
                message.protocol_counter.map(|value| value as i64),
                &message.ciphertext,
                &message.plaintext,
                message.created_at_unix_secs as i64,
            ],
        )?;
        tx.commit()
    }

    pub fn save_state_session_message_and_outbox(
        &mut self,
        local_identity_id: &str,
        local_identity_role: &str,
        local_identity_state: &[u8],
        conversation_id: &str,
        peer_id: &str,
        session_role: &str,
        session_state: &[u8],
        message: &MessageRecord,
        outbox: &OutboxItem,
    ) -> StorageResult<()> {
        let tx = self.conn.transaction()?;
        let now = now_unix_secs() as i64;

        tx.execute(
            "
            INSERT INTO local_identity (id, role, state, updated_at_unix_secs)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(id) DO UPDATE SET
                role = excluded.role,
                state = excluded.state,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![
                local_identity_id,
                local_identity_role,
                local_identity_state,
                now
            ],
        )?;
        tx.execute(
            "
            INSERT INTO sessions (conversation_id, peer_id, role, state, updated_at_unix_secs)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(conversation_id) DO UPDATE SET
                peer_id = excluded.peer_id,
                role = excluded.role,
                state = excluded.state,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![conversation_id, peer_id, session_role, session_state, now],
        )?;
        tx.execute(
            "
            INSERT OR IGNORE INTO messages (
                message_id,
                conversation_id,
                sender_id,
                recipient_id,
                direction,
                status,
                protocol_counter,
                ciphertext,
                plaintext,
                created_at_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ",
            params![
                &message.message_id,
                &message.conversation_id,
                &message.sender_id,
                &message.recipient_id,
                message.direction.as_str(),
                message.status.as_str(),
                message.protocol_counter.map(|value| value as i64),
                &message.ciphertext,
                &message.plaintext,
                message.created_at_unix_secs as i64,
            ],
        )?;
        tx.execute(
            "
            INSERT INTO outbox (
                message_id,
                recipient_id,
                payload,
                status,
                retry_count,
                created_at_unix_secs,
                last_attempt_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(message_id) DO UPDATE SET
                recipient_id = excluded.recipient_id,
                payload = excluded.payload,
                status = excluded.status
            ",
            params![
                &outbox.message_id,
                &outbox.recipient_id,
                &outbox.payload,
                outbox.status.as_str(),
                outbox.retry_count as i64,
                outbox.created_at_unix_secs as i64,
                outbox.last_attempt_unix_secs.map(|value| value as i64),
            ],
        )?;
        tx.commit()
    }

    pub fn pending_outbox_items(&self) -> StorageResult<Vec<OutboxItem>> {
        self.outbox_items_with_status(OutboxStatus::Pending)
    }

    pub fn outbox_item(&self, message_id: &str) -> StorageResult<Option<OutboxItem>> {
        self.conn
            .query_row(
                "
                SELECT
                    message_id,
                    recipient_id,
                    payload,
                    status,
                    retry_count,
                    created_at_unix_secs,
                    last_attempt_unix_secs
                FROM outbox
                WHERE message_id = ?1
                ",
                params![message_id],
                outbox_item_from_row,
            )
            .optional()
    }

    pub fn record_outbox_attempt(&self, message_id: &str) -> StorageResult<()> {
        self.conn.execute(
            "
            UPDATE outbox
            SET retry_count = retry_count + 1,
                last_attempt_unix_secs = ?2
            WHERE message_id = ?1
            ",
            params![message_id, now_unix_secs() as i64],
        )?;
        Ok(())
    }

    pub fn mark_outbox_delivered(&self, message_id: &str) -> StorageResult<()> {
        self.conn.execute(
            "
            UPDATE outbox
            SET status = 'delivered',
                last_attempt_unix_secs = ?2
            WHERE message_id = ?1
            ",
            params![message_id, now_unix_secs() as i64],
        )?;
        Ok(())
    }

    pub fn accept_message_once(&self, message_id: &str) -> StorageResult<bool> {
        let inserted = self.conn.execute(
            "
            INSERT OR IGNORE INTO accepted_messages (message_id, accepted_at_unix_secs)
            VALUES (?1, ?2)
            ",
            params![message_id, now_unix_secs() as i64],
        )?;
        Ok(inserted == 1)
    }

    pub fn messages_for_conversation(
        &self,
        conversation_id: &str,
    ) -> StorageResult<Vec<MessageRecord>> {
        let mut statement = self.conn.prepare(
            "
            SELECT
                message_id,
                conversation_id,
                sender_id,
                recipient_id,
                direction,
                status,
                protocol_counter,
                ciphertext,
                plaintext,
                created_at_unix_secs
            FROM messages
            WHERE conversation_id = ?1
            ORDER BY created_at_unix_secs, protocol_counter, message_id
            ",
        )?;

        let rows = statement.query_map(params![conversation_id], |row| {
            let direction: String = row.get(4)?;
            let status: String = row.get(5)?;
            let protocol_counter: Option<i64> = row.get(6)?;
            let created_at: i64 = row.get(9)?;

            Ok(MessageRecord {
                message_id: row.get(0)?,
                conversation_id: row.get(1)?,
                sender_id: row.get(2)?,
                recipient_id: row.get(3)?,
                direction: MessageDirection::from_str(&direction),
                status: MessageStatus::from_str(&status),
                protocol_counter: protocol_counter.map(|value| value as u64),
                ciphertext: row.get(7)?,
                plaintext: row.get(8)?,
                created_at_unix_secs: created_at as u64,
            })
        })?;

        rows.collect()
    }

    fn outbox_items_with_status(&self, status: OutboxStatus) -> StorageResult<Vec<OutboxItem>> {
        let mut statement = self.conn.prepare(
            "
            SELECT
                message_id,
                recipient_id,
                payload,
                status,
                retry_count,
                created_at_unix_secs,
                last_attempt_unix_secs
            FROM outbox
            WHERE status = ?1
            ORDER BY created_at_unix_secs, message_id
            ",
        )?;

        let rows = statement.query_map(params![status.as_str()], outbox_item_from_row)?;
        rows.collect()
    }
}

fn outbox_item_from_row(row: &rusqlite::Row<'_>) -> StorageResult<OutboxItem> {
    let status: String = row.get(3)?;
    let retry_count: i64 = row.get(4)?;
    let created_at: i64 = row.get(5)?;
    let last_attempt: Option<i64> = row.get(6)?;

    Ok(OutboxItem {
        message_id: row.get(0)?,
        recipient_id: row.get(1)?,
        payload: row.get(2)?,
        status: OutboxStatus::from_str(&status),
        retry_count: retry_count as u64,
        created_at_unix_secs: created_at as u64,
        last_attempt_unix_secs: last_attempt.map(|value| value as u64),
    })
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_persists_session_and_message_together() {
        let mut storage = Storage::open_in_memory().expect("open storage");
        let message = MessageRecord {
            message_id: "message-1".to_string(),
            conversation_id: "alice-bob".to_string(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            direction: MessageDirection::Sent,
            status: MessageStatus::Sent,
            protocol_counter: Some(0),
            ciphertext: vec![1, 2, 3],
            plaintext: Some("hello".to_string()),
            created_at_unix_secs: 10,
        };

        storage
            .save_state_session_and_insert_message(
                "alice",
                "alice",
                b"alice-state",
                "alice-bob",
                "bob",
                "alice",
                b"session-state",
                &message,
            )
            .expect("transaction commits");

        assert_eq!(
            storage.load_local_identity("alice").expect("identity"),
            Some(b"alice-state".to_vec())
        );
        assert_eq!(
            storage.load_session("alice-bob").expect("session"),
            Some(b"session-state".to_vec())
        );
        assert_eq!(
            storage
                .messages_for_conversation("alice-bob")
                .expect("messages")[0]
                .ciphertext,
            vec![1, 2, 3]
        );
    }

    #[test]
    fn outbox_stays_pending_until_ack_marks_delivered() {
        let mut storage = Storage::open_in_memory().expect("open storage");
        let message = MessageRecord {
            message_id: "message-1".to_string(),
            conversation_id: "alice-bob".to_string(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            direction: MessageDirection::Sent,
            status: MessageStatus::Sent,
            protocol_counter: Some(0),
            ciphertext: vec![1, 2, 3],
            plaintext: Some("hello".to_string()),
            created_at_unix_secs: 10,
        };
        let outbox = OutboxItem {
            message_id: message.message_id.clone(),
            recipient_id: "bob".to_string(),
            payload: vec![9, 8, 7],
            status: OutboxStatus::Pending,
            retry_count: 0,
            created_at_unix_secs: 10,
            last_attempt_unix_secs: None,
        };

        storage
            .save_state_session_message_and_outbox(
                "alice",
                "alice",
                b"alice-state",
                "alice-bob",
                "bob",
                "alice",
                b"session-state",
                &message,
                &outbox,
            )
            .expect("transaction commits");

        assert_eq!(storage.pending_outbox_items().expect("pending").len(), 1);
        storage
            .record_outbox_attempt("message-1")
            .expect("attempt recorded");
        assert_eq!(
            storage
                .outbox_item("message-1")
                .expect("outbox item")
                .expect("message exists")
                .retry_count,
            1
        );
        storage
            .mark_outbox_delivered("message-1")
            .expect("delivered");
        assert!(storage
            .pending_outbox_items()
            .expect("pending after ack")
            .is_empty());
    }

    #[test]
    fn accepted_messages_deduplicate_retries() {
        let storage = Storage::open_in_memory().expect("open storage");

        assert!(storage
            .accept_message_once("message-1")
            .expect("first accept"));
        assert!(!storage
            .accept_message_once("message-1")
            .expect("duplicate accept"));
    }
}
