use rusqlite::{params, Connection, OptionalExtension};
use std::{
    collections::BTreeMap,
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

pub type VersionVector = BTreeMap<String, u64>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub device_id: String,
    pub counter: u64,
    pub conversation_id: String,
    pub event_type: String,
    pub message_id: Option<String>,
    pub payload: Vec<u8>,
    pub created_at_unix_secs: u64,
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

            CREATE TABLE IF NOT EXISTS device_pair_sessions (
                local_device_id TEXT NOT NULL,
                remote_device_id TEXT NOT NULL,
                state BLOB NOT NULL,
                updated_at_unix_secs INTEGER NOT NULL,
                PRIMARY KEY (local_device_id, remote_device_id)
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

            CREATE TABLE IF NOT EXISTS device_counters (
                device_id TEXT PRIMARY KEY,
                next_counter INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS event_history (
                device_id TEXT NOT NULL,
                counter INTEGER NOT NULL,
                conversation_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message_id TEXT,
                payload BLOB NOT NULL,
                created_at_unix_secs INTEGER NOT NULL,
                PRIMARY KEY (device_id, counter)
            );

            CREATE INDEX IF NOT EXISTS event_history_conversation_idx
            ON event_history (conversation_id, device_id, counter);

            CREATE TABLE IF NOT EXISTS version_vectors (
                conversation_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                contiguous_counter INTEGER NOT NULL,
                PRIMARY KEY (conversation_id, device_id)
            );

            CREATE TABLE IF NOT EXISTS account_identities (
                account_id TEXT PRIMARY KEY,
                account_public_key BLOB NOT NULL,
                account_secret_key BLOB,
                updated_at_unix_secs INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS device_identities (
                device_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                device_ed25519_public_key BLOB NOT NULL,
                device_ed25519_secret_key BLOB NOT NULL,
                device_x25519_public_key BLOB NOT NULL,
                device_x25519_private_key BLOB NOT NULL,
                updated_at_unix_secs INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS device_certificates (
                account_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                certificate BLOB NOT NULL,
                updated_at_unix_secs INTEGER NOT NULL,
                PRIMARY KEY (account_id, device_id)
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

    pub fn save_device_pair_session(
        &self,
        local_device_id: &str,
        remote_device_id: &str,
        state: &[u8],
    ) -> StorageResult<()> {
        self.conn.execute(
            "
            INSERT INTO device_pair_sessions (
                local_device_id,
                remote_device_id,
                state,
                updated_at_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(local_device_id, remote_device_id) DO UPDATE SET
                state = excluded.state,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![
                local_device_id,
                remote_device_id,
                state,
                now_unix_secs() as i64
            ],
        )?;
        Ok(())
    }

    pub fn load_device_pair_session(
        &self,
        local_device_id: &str,
        remote_device_id: &str,
    ) -> StorageResult<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "
                SELECT state
                FROM device_pair_sessions
                WHERE local_device_id = ?1
                  AND remote_device_id = ?2
                ",
                params![local_device_id, remote_device_id],
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

    pub fn save_device_pair_session_and_outbox(
        &mut self,
        local_device_id: &str,
        remote_device_id: &str,
        session_state: &[u8],
        outbox: &OutboxItem,
    ) -> StorageResult<()> {
        let tx = self.conn.transaction()?;
        let now = now_unix_secs() as i64;

        tx.execute(
            "
            INSERT INTO device_pair_sessions (
                local_device_id,
                remote_device_id,
                state,
                updated_at_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(local_device_id, remote_device_id) DO UPDATE SET
                state = excluded.state,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![local_device_id, remote_device_id, session_state, now],
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

    pub fn save_account_identity(
        &self,
        account_id: &str,
        account_public_key: &[u8],
        account_secret_key: Option<&[u8]>,
    ) -> StorageResult<()> {
        self.conn.execute(
            "
            INSERT INTO account_identities (
                account_id,
                account_public_key,
                account_secret_key,
                updated_at_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(account_id) DO UPDATE SET
                account_public_key = excluded.account_public_key,
                account_secret_key = excluded.account_secret_key,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![
                account_id,
                account_public_key,
                account_secret_key,
                now_unix_secs() as i64
            ],
        )?;
        Ok(())
    }

    pub fn load_account_secret_key(&self, account_id: &str) -> StorageResult<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT account_secret_key FROM account_identities WHERE account_id = ?1",
                params![account_id],
                |row| row.get(0),
            )
            .optional()
            .map(Option::flatten)
    }

    pub fn save_device_identity(
        &self,
        device_id: &str,
        account_id: &str,
        device_ed25519_public_key: &[u8],
        device_ed25519_secret_key: &[u8],
        device_x25519_public_key: &[u8],
        device_x25519_private_key: &[u8],
    ) -> StorageResult<()> {
        self.conn.execute(
            "
            INSERT INTO device_identities (
                device_id,
                account_id,
                device_ed25519_public_key,
                device_ed25519_secret_key,
                device_x25519_public_key,
                device_x25519_private_key,
                updated_at_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(device_id) DO UPDATE SET
                account_id = excluded.account_id,
                device_ed25519_public_key = excluded.device_ed25519_public_key,
                device_ed25519_secret_key = excluded.device_ed25519_secret_key,
                device_x25519_public_key = excluded.device_x25519_public_key,
                device_x25519_private_key = excluded.device_x25519_private_key,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![
                device_id,
                account_id,
                device_ed25519_public_key,
                device_ed25519_secret_key,
                device_x25519_public_key,
                device_x25519_private_key,
                now_unix_secs() as i64
            ],
        )?;
        Ok(())
    }

    pub fn load_device_identity(&self, device_id: &str) -> StorageResult<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "
                SELECT
                    account_id,
                    device_ed25519_secret_key,
                    device_x25519_private_key
                FROM device_identities
                WHERE device_id = ?1
                ",
                params![device_id],
                |row| {
                    let account_id: String = row.get(0)?;
                    let device_ed25519_secret_key: Vec<u8> = row.get(1)?;
                    let device_x25519_private_key: Vec<u8> = row.get(2)?;
                    Ok(bincode::serialize(&(
                        account_id,
                        device_id.to_string(),
                        device_ed25519_secret_key,
                        device_x25519_private_key,
                    ))
                    .expect("serializing loaded device identity cannot fail"))
                },
            )
            .optional()
    }

    pub fn save_device_certificate(
        &self,
        account_id: &str,
        device_id: &str,
        certificate: &[u8],
    ) -> StorageResult<()> {
        self.conn.execute(
            "
            INSERT INTO device_certificates (
                account_id,
                device_id,
                certificate,
                updated_at_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(account_id, device_id) DO UPDATE SET
                certificate = excluded.certificate,
                updated_at_unix_secs = excluded.updated_at_unix_secs
            ",
            params![account_id, device_id, certificate, now_unix_secs() as i64],
        )?;
        Ok(())
    }

    pub fn device_certificates_for_account(&self, account_id: &str) -> StorageResult<Vec<Vec<u8>>> {
        let mut statement = self.conn.prepare(
            "
            SELECT certificate
            FROM device_certificates
            WHERE account_id = ?1
            ORDER BY device_id
            ",
        )?;
        let rows = statement.query_map(params![account_id], |row| row.get(0))?;
        rows.collect()
    }

    pub fn next_local_event_counter(&mut self, device_id: &str) -> StorageResult<u64> {
        let tx = self.conn.transaction()?;
        let current = tx
            .query_row(
                "SELECT next_counter FROM device_counters WHERE device_id = ?1",
                params![device_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(1);
        let next = current + 1;

        tx.execute(
            "
            INSERT INTO device_counters (device_id, next_counter)
            VALUES (?1, ?2)
            ON CONFLICT(device_id) DO UPDATE SET
                next_counter = excluded.next_counter
            ",
            params![device_id, next],
        )?;
        tx.commit()?;
        Ok(current as u64)
    }

    pub fn append_event(&self, event: &EventRecord) -> StorageResult<bool> {
        let inserted = self.conn.execute(
            "
            INSERT OR IGNORE INTO event_history (
                device_id,
                counter,
                conversation_id,
                event_type,
                message_id,
                payload,
                created_at_unix_secs
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ",
            params![
                &event.device_id,
                event.counter as i64,
                &event.conversation_id,
                &event.event_type,
                &event.message_id,
                &event.payload,
                event.created_at_unix_secs as i64,
            ],
        )?;

        self.refresh_vector_for_device(&event.conversation_id, &event.device_id)?;
        Ok(inserted == 1)
    }

    pub fn append_events(&self, events: &[EventRecord]) -> StorageResult<usize> {
        let mut inserted = 0;
        for event in events {
            if self.append_event(event)? {
                inserted += 1;
            }
        }
        Ok(inserted)
    }

    pub fn version_vector(&self, conversation_id: &str) -> StorageResult<VersionVector> {
        let mut statement = self.conn.prepare(
            "
            SELECT device_id, contiguous_counter
            FROM version_vectors
            WHERE conversation_id = ?1
            ORDER BY device_id
            ",
        )?;
        let rows = statement.query_map(params![conversation_id], |row| {
            let device_id: String = row.get(0)?;
            let counter: i64 = row.get(1)?;
            Ok((device_id, counter as u64))
        })?;

        rows.collect()
    }

    pub fn missing_events_for(
        &self,
        conversation_id: &str,
        peer_vector: &VersionVector,
    ) -> StorageResult<Vec<EventRecord>> {
        let mut statement = self.conn.prepare(
            "
            SELECT
                device_id,
                counter,
                conversation_id,
                event_type,
                message_id,
                payload,
                created_at_unix_secs
            FROM event_history
            WHERE conversation_id = ?1
            ORDER BY device_id, counter
            ",
        )?;
        let rows = statement.query_map(params![conversation_id], event_from_row)?;
        let mut missing = Vec::new();

        for row in rows {
            let event = row?;
            let seen = peer_vector.get(&event.device_id).copied().unwrap_or(0);
            if event.counter > seen {
                missing.push(event);
            }
        }

        Ok(missing)
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

    fn refresh_vector_for_device(
        &self,
        conversation_id: &str,
        device_id: &str,
    ) -> StorageResult<()> {
        let mut statement = self.conn.prepare(
            "
            SELECT counter
            FROM event_history
            WHERE conversation_id = ?1
              AND device_id = ?2
            ORDER BY counter
            ",
        )?;
        let counters = statement.query_map(params![conversation_id, device_id], |row| {
            row.get::<_, i64>(0)
        })?;

        let mut contiguous = 0;
        for counter in counters {
            let counter = counter? as u64;
            if counter == contiguous + 1 {
                contiguous = counter;
            } else if counter > contiguous + 1 {
                break;
            }
        }

        self.conn.execute(
            "
            INSERT INTO version_vectors (conversation_id, device_id, contiguous_counter)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(conversation_id, device_id) DO UPDATE SET
                contiguous_counter = excluded.contiguous_counter
            ",
            params![conversation_id, device_id, contiguous as i64],
        )?;
        Ok(())
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

fn event_from_row(row: &rusqlite::Row<'_>) -> StorageResult<EventRecord> {
    let counter: i64 = row.get(1)?;
    let created_at: i64 = row.get(6)?;

    Ok(EventRecord {
        device_id: row.get(0)?,
        counter: counter as u64,
        conversation_id: row.get(2)?,
        event_type: row.get(3)?,
        message_id: row.get(4)?,
        payload: row.get(5)?,
        created_at_unix_secs: created_at as u64,
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
    fn device_pair_sessions_are_keyed_by_both_devices() {
        let mut storage = Storage::open_in_memory().expect("open storage");
        let laptop_outbox = OutboxItem {
            message_id: "logical-1:alice-laptop".to_string(),
            recipient_id: "alice-laptop".to_string(),
            payload: b"laptop-envelope".to_vec(),
            status: OutboxStatus::Pending,
            retry_count: 0,
            created_at_unix_secs: 10,
            last_attempt_unix_secs: None,
        };
        let phone_outbox = OutboxItem {
            message_id: "logical-1:alice-phone".to_string(),
            recipient_id: "alice-phone".to_string(),
            payload: b"phone-envelope".to_vec(),
            status: OutboxStatus::Pending,
            retry_count: 0,
            created_at_unix_secs: 10,
            last_attempt_unix_secs: None,
        };

        storage
            .save_device_pair_session_and_outbox(
                "bob-device",
                "alice-laptop",
                b"laptop-session",
                &laptop_outbox,
            )
            .expect("save laptop session");
        storage
            .save_device_pair_session_and_outbox(
                "bob-device",
                "alice-phone",
                b"phone-session",
                &phone_outbox,
            )
            .expect("save phone session");

        assert_eq!(
            storage
                .load_device_pair_session("bob-device", "alice-laptop")
                .expect("load laptop"),
            Some(b"laptop-session".to_vec())
        );
        assert_eq!(
            storage
                .load_device_pair_session("bob-device", "alice-phone")
                .expect("load phone"),
            Some(b"phone-session".to_vec())
        );

        storage
            .mark_outbox_delivered("logical-1:alice-laptop")
            .expect("deliver laptop");
        let pending = storage.pending_outbox_items().expect("pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].recipient_id, "alice-phone");
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

    #[test]
    fn sync_exchanges_only_missing_events_and_updates_vectors() {
        let alice = Storage::open_in_memory().expect("alice storage");
        let bob = Storage::open_in_memory().expect("bob storage");
        let conversation = "conversation";

        for event in [
            event("AliceDevice", 1),
            event("AliceDevice", 2),
            event("AliceDevice", 3),
            event("BobDevice", 1),
        ] {
            alice.append_event(&event).expect("alice append");
        }
        for event in [
            event("AliceDevice", 1),
            event("AliceDevice", 2),
            event("BobDevice", 1),
            event("BobDevice", 2),
        ] {
            bob.append_event(&event).expect("bob append");
        }

        assert_eq!(alice.version_vector(conversation).expect("alice vector"), {
            let mut vector = VersionVector::new();
            vector.insert("AliceDevice".to_string(), 3);
            vector.insert("BobDevice".to_string(), 1);
            vector
        });
        assert_eq!(bob.version_vector(conversation).expect("bob vector"), {
            let mut vector = VersionVector::new();
            vector.insert("AliceDevice".to_string(), 2);
            vector.insert("BobDevice".to_string(), 2);
            vector
        });

        let bob_to_alice = bob
            .missing_events_for(conversation, &alice.version_vector(conversation).unwrap())
            .expect("bob missing for alice");
        let alice_to_bob = alice
            .missing_events_for(conversation, &bob.version_vector(conversation).unwrap())
            .expect("alice missing for bob");

        assert_eq!(
            bob_to_alice
                .iter()
                .map(|event| (&event.device_id, event.counter))
                .collect::<Vec<_>>(),
            vec![(&"BobDevice".to_string(), 2)]
        );
        assert_eq!(
            alice_to_bob
                .iter()
                .map(|event| (&event.device_id, event.counter))
                .collect::<Vec<_>>(),
            vec![(&"AliceDevice".to_string(), 3)]
        );

        alice.append_events(&bob_to_alice).expect("alice receives");
        bob.append_events(&alice_to_bob).expect("bob receives");

        let mut expected = VersionVector::new();
        expected.insert("AliceDevice".to_string(), 3);
        expected.insert("BobDevice".to_string(), 2);
        assert_eq!(alice.version_vector(conversation).unwrap(), expected);
        assert_eq!(bob.version_vector(conversation).unwrap(), expected);
    }

    #[test]
    fn duplicate_event_delivery_is_idempotent() {
        let storage = Storage::open_in_memory().expect("storage");
        let event = event("AliceDevice", 1);

        assert!(storage.append_event(&event).expect("first append"));
        assert!(!storage.append_event(&event).expect("duplicate append"));
        assert_eq!(
            storage.version_vector("conversation").expect("vector")["AliceDevice"],
            1
        );
    }

    #[test]
    fn out_of_order_event_arrival_advances_when_gap_fills() {
        let storage = Storage::open_in_memory().expect("storage");

        storage
            .append_event(&event("AliceDevice", 2))
            .expect("append two first");
        assert_eq!(
            storage
                .version_vector("conversation")
                .expect("vector after gap")["AliceDevice"],
            0
        );

        storage
            .append_event(&event("AliceDevice", 1))
            .expect("append one");
        assert_eq!(
            storage
                .version_vector("conversation")
                .expect("vector after fill")["AliceDevice"],
            2
        );
    }

    #[test]
    fn missing_counter_gap_blocks_vector_advancement() {
        let storage = Storage::open_in_memory().expect("storage");

        storage.append_event(&event("AliceDevice", 1)).unwrap();
        storage.append_event(&event("AliceDevice", 2)).unwrap();
        storage.append_event(&event("AliceDevice", 4)).unwrap();

        assert_eq!(
            storage.version_vector("conversation").unwrap()["AliceDevice"],
            2
        );
    }

    #[test]
    fn local_counter_survives_storage_reopen() {
        let path = std::env::temp_dir().join(format!(
            "ciphermesh-sync-counter-{}.sqlite",
            now_unix_secs()
        ));

        {
            let mut storage = Storage::open(&path).expect("open first");
            assert_eq!(
                storage
                    .next_local_event_counter("AliceDevice")
                    .expect("first counter"),
                1
            );
            assert_eq!(
                storage
                    .next_local_event_counter("AliceDevice")
                    .expect("second counter"),
                2
            );
        }

        {
            let mut storage = Storage::open(&path).expect("open second");
            assert_eq!(
                storage
                    .next_local_event_counter("AliceDevice")
                    .expect("third counter"),
                3
            );
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn account_device_identity_records_persist() {
        let storage = Storage::open_in_memory().expect("storage");

        storage
            .save_account_identity("acct-1", b"account-public", Some(b"account-secret"))
            .expect("save account");
        storage
            .save_device_identity(
                "dev-laptop",
                "acct-1",
                b"device-ed-public",
                b"device-ed-secret",
                b"device-x-public",
                b"device-x-private",
            )
            .expect("save laptop");
        storage
            .save_device_certificate("acct-1", "dev-laptop", b"cert-laptop")
            .expect("save laptop cert");
        storage
            .save_device_certificate("acct-1", "dev-phone", b"cert-phone")
            .expect("save phone cert");

        assert_eq!(
            storage.load_account_secret_key("acct-1").expect("secret"),
            Some(b"account-secret".to_vec())
        );
        assert_eq!(
            storage
                .device_certificates_for_account("acct-1")
                .expect("certs"),
            vec![b"cert-laptop".to_vec(), b"cert-phone".to_vec()]
        );
    }

    fn event(device_id: &str, counter: u64) -> EventRecord {
        EventRecord {
            device_id: device_id.to_string(),
            counter,
            conversation_id: "conversation".to_string(),
            event_type: "message".to_string(),
            message_id: Some(format!("{device_id}-{counter}")),
            payload: format!("{device_id}:{counter}").into_bytes(),
            created_at_unix_secs: 10 + counter,
        }
    }
}
