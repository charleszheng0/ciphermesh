use rusqlite::{params, Connection};
use std::{
    error::Error,
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub type MailboxStorageResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEnvelopeRecord {
    pub message_id: String,
    pub recipient_token: String,
    pub encrypted_payload: Vec<u8>,
    pub created_at_unix_secs: u64,
    pub expires_at_unix_secs: Option<u64>,
}

pub struct MailboxStorage {
    conn: Connection,
    max_pending_envelopes: usize,
}

impl MailboxStorage {
    pub fn open(
        path: impl AsRef<Path>,
        max_pending_envelopes: usize,
    ) -> MailboxStorageResult<Self> {
        let conn = Connection::open(path)?;
        let storage = Self {
            conn,
            max_pending_envelopes,
        };
        storage.init()?;
        Ok(storage)
    }

    pub fn open_in_memory(max_pending_envelopes: usize) -> MailboxStorageResult<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self {
            conn,
            max_pending_envelopes,
        };
        storage.init()?;
        Ok(storage)
    }

    fn init(&self) -> MailboxStorageResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS mailbox_envelopes (
                message_id TEXT PRIMARY KEY,
                recipient_token TEXT NOT NULL,
                encrypted_payload BLOB NOT NULL,
                status TEXT NOT NULL,
                created_at_unix_secs INTEGER NOT NULL,
                expires_at_unix_secs INTEGER,
                delivered_at_unix_secs INTEGER
            );

            CREATE INDEX IF NOT EXISTS mailbox_pending_recipient_idx
            ON mailbox_envelopes (recipient_token, status, created_at_unix_secs);
            ",
        )?;
        Ok(())
    }

    pub fn deposit(
        &self,
        envelope: &MailboxEnvelopeRecord,
        now: u64,
    ) -> MailboxStorageResult<bool> {
        self.expire(now)?;

        if self.pending_count()? >= self.max_pending_envelopes
            && !self.has_envelope(&envelope.message_id)?
        {
            return Err(io::Error::other("mailbox storage is full").into());
        }

        let inserted = self.conn.execute(
            "
            INSERT OR IGNORE INTO mailbox_envelopes (
                message_id,
                recipient_token,
                encrypted_payload,
                status,
                created_at_unix_secs,
                expires_at_unix_secs
            )
            VALUES (?1, ?2, ?3, 'pending', ?4, ?5)
            ",
            params![
                &envelope.message_id,
                &envelope.recipient_token,
                &envelope.encrypted_payload,
                envelope.created_at_unix_secs as i64,
                envelope.expires_at_unix_secs.map(|value| value as i64),
            ],
        )?;
        Ok(inserted == 1)
    }

    pub fn fetch_pending(
        &self,
        recipient_token: &str,
        now: u64,
    ) -> MailboxStorageResult<Vec<MailboxEnvelopeRecord>> {
        self.expire(now)?;
        let mut statement = self.conn.prepare(
            "
            SELECT message_id, recipient_token, encrypted_payload, created_at_unix_secs, expires_at_unix_secs
            FROM mailbox_envelopes
            WHERE recipient_token = ?1
              AND status = 'pending'
              AND (expires_at_unix_secs IS NULL OR expires_at_unix_secs > ?2)
            ORDER BY created_at_unix_secs, message_id
            ",
        )?;
        let rows = statement.query_map(params![recipient_token, now as i64], |row| {
            let created_at: i64 = row.get(3)?;
            let expires_at: Option<i64> = row.get(4)?;
            Ok(MailboxEnvelopeRecord {
                message_id: row.get(0)?,
                recipient_token: row.get(1)?,
                encrypted_payload: row.get(2)?,
                created_at_unix_secs: created_at as u64,
                expires_at_unix_secs: expires_at.map(|value| value as u64),
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn acknowledge_retrieval(&self, message_id: &str, now: u64) -> MailboxStorageResult<()> {
        self.conn.execute(
            "
            UPDATE mailbox_envelopes
            SET status = 'delivered',
                delivered_at_unix_secs = ?2
            WHERE message_id = ?1
            ",
            params![message_id, now as i64],
        )?;
        Ok(())
    }

    pub fn pending_count(&self) -> MailboxStorageResult<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM mailbox_envelopes WHERE status = 'pending'",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn expire(&self, now: u64) -> MailboxStorageResult<()> {
        self.conn.execute(
            "
            UPDATE mailbox_envelopes
            SET status = 'expired'
            WHERE status = 'pending'
              AND expires_at_unix_secs IS NOT NULL
              AND expires_at_unix_secs <= ?1
            ",
            params![now as i64],
        )?;
        Ok(())
    }

    fn has_envelope(&self, message_id: &str) -> MailboxStorageResult<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM mailbox_envelopes WHERE message_id = ?1",
            params![message_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }
}

pub fn mailbox_now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(id: &str) -> MailboxEnvelopeRecord {
        MailboxEnvelopeRecord {
            message_id: id.to_string(),
            recipient_token: "recipient".to_string(),
            encrypted_payload: vec![1, 2, 3],
            created_at_unix_secs: 10,
            expires_at_unix_secs: Some(200),
        }
    }

    #[test]
    fn duplicate_deposit_does_not_create_duplicate_rows() {
        let storage = MailboxStorage::open_in_memory(4).expect("open mailbox");

        assert!(storage.deposit(&envelope("message-1"), 100).expect("first"));
        assert!(!storage
            .deposit(&envelope("message-1"), 100)
            .expect("duplicate"));
        assert_eq!(storage.pending_count().expect("count"), 1);
    }

    #[test]
    fn fetch_keeps_pending_until_retrieval_ack() {
        let storage = MailboxStorage::open_in_memory(4).expect("open mailbox");
        storage
            .deposit(&envelope("message-1"), 100)
            .expect("deposit");

        assert_eq!(
            storage
                .fetch_pending("recipient", 100)
                .expect("first fetch")
                .len(),
            1
        );
        assert_eq!(
            storage
                .fetch_pending("recipient", 100)
                .expect("second fetch")
                .len(),
            1
        );

        storage
            .acknowledge_retrieval("message-1", 101)
            .expect("ack");
        assert!(storage
            .fetch_pending("recipient", 102)
            .expect("after ack")
            .is_empty());
    }

    #[test]
    fn expired_envelopes_are_not_returned() {
        let storage = MailboxStorage::open_in_memory(4).expect("open mailbox");
        storage
            .deposit(&envelope("message-1"), 100)
            .expect("deposit");

        assert!(storage
            .fetch_pending("recipient", 201)
            .expect("expired fetch")
            .is_empty());
    }
}
