use crate::storage::EventRecord;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventPosition {
    pub device_id: String,
    pub counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReactionAddId {
    pub device_id: String,
    pub counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversationEvent {
    MessageCreated {
        message_id: String,
        author_id: String,
        payload: Vec<u8>,
    },
    MessageDeleted {
        message_id: String,
    },
    ReactionAdded {
        message_id: String,
        reaction: String,
        actor_id: String,
    },
    ReactionRemoved {
        reaction_add: ReactionAddId,
    },
    ReadAdvanced {
        actor_id: String,
        read_device_id: String,
        read_counter: u64,
    },
}

impl ConversationEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::MessageCreated { .. } => "MessageCreated",
            Self::MessageDeleted { .. } => "MessageDeleted",
            Self::ReactionAdded { .. } => "ReactionAdded",
            Self::ReactionRemoved { .. } => "ReactionRemoved",
            Self::ReadAdvanced { .. } => "ReadAdvanced",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VisibleReaction {
    pub reaction: String,
    pub actor_id: String,
    pub add: ReactionAddId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageState {
    pub message_id: String,
    pub author_id: String,
    pub payload: Vec<u8>,
    pub deleted: bool,
    pub reactions: BTreeSet<VisibleReaction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConversationState {
    pub messages: BTreeMap<String, MessageState>,
    pub tombstones: BTreeSet<String>,
    pub read_frontiers: BTreeMap<String, BTreeMap<String, u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactionAdd {
    message_id: String,
    reaction: String,
    actor_id: String,
}

pub fn event_record(
    conversation_id: &str,
    device_id: &str,
    counter: u64,
    event: ConversationEvent,
) -> Result<EventRecord, bincode::Error> {
    let message_id = match &event {
        ConversationEvent::MessageCreated { message_id, .. }
        | ConversationEvent::MessageDeleted { message_id } => Some(message_id.clone()),
        ConversationEvent::ReactionAdded { message_id, .. } => Some(message_id.clone()),
        ConversationEvent::ReactionRemoved { .. } | ConversationEvent::ReadAdvanced { .. } => None,
    };

    Ok(EventRecord {
        device_id: device_id.to_string(),
        counter,
        conversation_id: conversation_id.to_string(),
        event_type: event.event_type().to_string(),
        message_id,
        payload: bincode::serialize(&event)?,
        created_at_unix_secs: 0,
    })
}

pub fn materialize_conversation(events: &[EventRecord]) -> ConversationState {
    let mut messages = BTreeMap::<String, MessageState>::new();
    let mut tombstones = BTreeSet::<String>::new();
    let mut reaction_adds = BTreeMap::<ReactionAddId, ReactionAdd>::new();
    let mut removed_reactions = BTreeSet::<ReactionAddId>::new();
    let mut read_frontiers = BTreeMap::<String, BTreeMap<String, u64>>::new();

    for record in events {
        let Ok(event) = bincode::deserialize::<ConversationEvent>(&record.payload) else {
            continue;
        };

        match event {
            ConversationEvent::MessageCreated {
                message_id,
                author_id,
                payload,
            } => {
                messages.entry(message_id.clone()).or_insert(MessageState {
                    deleted: tombstones.contains(&message_id),
                    message_id,
                    author_id,
                    payload,
                    reactions: BTreeSet::new(),
                });
            }
            ConversationEvent::MessageDeleted { message_id } => {
                tombstones.insert(message_id.clone());
                if let Some(message) = messages.get_mut(&message_id) {
                    message.deleted = true;
                }
            }
            ConversationEvent::ReactionAdded {
                message_id,
                reaction,
                actor_id,
            } => {
                reaction_adds.insert(
                    ReactionAddId {
                        device_id: record.device_id.clone(),
                        counter: record.counter,
                    },
                    ReactionAdd {
                        message_id,
                        reaction,
                        actor_id,
                    },
                );
            }
            ConversationEvent::ReactionRemoved { reaction_add } => {
                removed_reactions.insert(reaction_add);
            }
            ConversationEvent::ReadAdvanced {
                actor_id,
                read_device_id,
                read_counter,
            } => {
                let frontier = read_frontiers.entry(actor_id).or_default();
                let current = frontier.entry(read_device_id).or_default();
                *current = (*current).max(read_counter);
            }
        }
    }

    for (add, reaction) in reaction_adds {
        if removed_reactions.contains(&add) {
            continue;
        }

        if let Some(message) = messages.get_mut(&reaction.message_id) {
            message.reactions.insert(VisibleReaction {
                reaction: reaction.reaction,
                actor_id: reaction.actor_id,
                add,
            });
        }
    }

    ConversationState {
        messages,
        tombstones,
        read_frontiers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Storage, VersionVector};

    const CONVERSATION: &str = "conversation";

    #[test]
    fn materialization_is_order_independent() {
        let events = vec![
            created(1),
            reaction_added("BobDevice", 1, "thumb", "+1", "bob"),
            reaction_added("AliceDevice", 2, "heart", "<3", "alice"),
        ];
        let reversed = events.iter().cloned().rev().collect::<Vec<_>>();

        assert_eq!(
            materialize_conversation(&events),
            materialize_conversation(&reversed)
        );
    }

    #[test]
    fn duplicate_events_are_idempotent() {
        let created = created(1);
        let add = reaction_added("BobDevice", 1, "thumb", "+1", "bob");
        let once = vec![created.clone(), add.clone()];
        let duplicated = vec![created, add.clone(), add];

        assert_eq!(
            materialize_conversation(&once),
            materialize_conversation(&duplicated)
        );
    }

    #[test]
    fn concurrent_reactions_converge_after_sync() {
        let alice = Storage::open_in_memory().expect("alice");
        let bob = Storage::open_in_memory().expect("bob");
        let created = created(1);
        let alice_reaction = reaction_added("AliceDevice", 2, "thumb", "+1", "alice");
        let bob_reaction = reaction_added("BobDevice", 1, "heart", "<3", "bob");

        alice.append_event(&created).unwrap();
        alice.append_event(&alice_reaction).unwrap();
        bob.append_event(&created).unwrap();
        bob.append_event(&bob_reaction).unwrap();

        sync_both(&alice, &bob);
        assert_eq!(
            materialize_conversation(&all_events(&alice)),
            materialize_conversation(&all_events(&bob))
        );
        assert_eq!(
            materialize_conversation(&all_events(&alice))
                .messages
                .get("message-1")
                .unwrap()
                .reactions
                .len(),
            2
        );
    }

    #[test]
    fn reaction_removal_converges() {
        let add = reaction_added("BobDevice", 1, "thumb", "+1", "bob");
        let remove = event_record(
            CONVERSATION,
            "AliceDevice",
            2,
            ConversationEvent::ReactionRemoved {
                reaction_add: ReactionAddId {
                    device_id: "BobDevice".to_string(),
                    counter: 1,
                },
            },
        )
        .unwrap();

        let first = vec![created(1), add.clone(), remove.clone()];
        let second = vec![remove, created(1), add];

        assert_eq!(
            materialize_conversation(&first),
            materialize_conversation(&second)
        );
        assert!(materialize_conversation(&first)
            .messages
            .get("message-1")
            .unwrap()
            .reactions
            .is_empty());
    }

    #[test]
    fn delete_tombstone_converges() {
        let create = created(1);
        let delete = event_record(
            CONVERSATION,
            "BobDevice",
            1,
            ConversationEvent::MessageDeleted {
                message_id: "message-1".to_string(),
            },
        )
        .unwrap();

        let first = vec![create.clone(), delete.clone()];
        let second = vec![delete, create];

        assert_eq!(
            materialize_conversation(&first),
            materialize_conversation(&second)
        );
        assert!(
            materialize_conversation(&first)
                .messages
                .get("message-1")
                .unwrap()
                .deleted
        );
    }

    #[test]
    fn read_state_merges_monotonically() {
        let read_five = event_record(
            CONVERSATION,
            "AliceDevice",
            1,
            ConversationEvent::ReadAdvanced {
                actor_id: "alice".to_string(),
                read_device_id: "BobDevice".to_string(),
                read_counter: 5,
            },
        )
        .unwrap();
        let read_seven = event_record(
            CONVERSATION,
            "AliceDevice",
            2,
            ConversationEvent::ReadAdvanced {
                actor_id: "alice".to_string(),
                read_device_id: "BobDevice".to_string(),
                read_counter: 7,
            },
        )
        .unwrap();
        let read_three = event_record(
            CONVERSATION,
            "AliceDevice",
            3,
            ConversationEvent::ReadAdvanced {
                actor_id: "alice".to_string(),
                read_device_id: "BobDevice".to_string(),
                read_counter: 3,
            },
        )
        .unwrap();

        let state = materialize_conversation(&[read_seven, read_three, read_five]);

        assert_eq!(state.read_frontiers["alice"]["BobDevice"], 7);
    }

    #[test]
    fn replicas_converge_after_phase_4d_sync() {
        let alice = Storage::open_in_memory().expect("alice");
        let bob = Storage::open_in_memory().expect("bob");
        let shared_create = created(1);
        let alice_reaction = reaction_added("AliceDevice", 2, "thumb", "+1", "alice");
        let bob_delete = event_record(
            CONVERSATION,
            "BobDevice",
            1,
            ConversationEvent::MessageDeleted {
                message_id: "message-1".to_string(),
            },
        )
        .unwrap();

        alice.append_event(&alice_reaction).unwrap();
        alice.append_event(&shared_create).unwrap();
        bob.append_event(&bob_delete).unwrap();
        bob.append_event(&shared_create).unwrap();

        sync_both(&alice, &bob);

        assert_eq!(
            materialize_conversation(&all_events(&alice)),
            materialize_conversation(&all_events(&bob))
        );
    }

    fn created(counter: u64) -> EventRecord {
        event_record(
            CONVERSATION,
            "AliceDevice",
            counter,
            ConversationEvent::MessageCreated {
                message_id: "message-1".to_string(),
                author_id: "alice".to_string(),
                payload: b"hello".to_vec(),
            },
        )
        .unwrap()
    }

    fn reaction_added(
        device_id: &str,
        counter: u64,
        _label: &str,
        reaction: &str,
        actor_id: &str,
    ) -> EventRecord {
        event_record(
            CONVERSATION,
            device_id,
            counter,
            ConversationEvent::ReactionAdded {
                message_id: "message-1".to_string(),
                reaction: reaction.to_string(),
                actor_id: actor_id.to_string(),
            },
        )
        .unwrap()
    }

    fn all_events(storage: &Storage) -> Vec<EventRecord> {
        let empty = VersionVector::new();
        storage.missing_events_for(CONVERSATION, &empty).unwrap()
    }

    fn sync_both(alice: &Storage, bob: &Storage) {
        let alice_vector = alice.version_vector(CONVERSATION).unwrap();
        let bob_vector = bob.version_vector(CONVERSATION).unwrap();
        let bob_to_alice = bob.missing_events_for(CONVERSATION, &alice_vector).unwrap();
        let alice_to_bob = alice.missing_events_for(CONVERSATION, &bob_vector).unwrap();

        alice.append_events(&bob_to_alice).unwrap();
        bob.append_events(&alice_to_bob).unwrap();
    }
}
