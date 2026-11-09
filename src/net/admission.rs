//! Authentication and admission belong to the original actual-connection table.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use iroh::{endpoint::Connection, PublicKey};
use n0_error::e;
use tokio::sync::watch;

use super::{ConnId, ConnectionAuthenticator, Error};

#[derive(Clone, Debug, Default)]
pub(super) struct ConnectionRegistry(Arc<Mutex<RegistryState>>);

#[derive(Debug, Default)]
struct RegistryState {
    sealed: bool,
    connections: HashMap<ConnId, Arc<ConnectionRecord>>,
}

#[derive(Debug)]
struct ConnectionRecord {
    connection: Connection,
    state: watch::Sender<AdmissionState>,
}

#[derive(Clone, Debug)]
enum AdmissionState {
    Authenticating,
    Verified(PublicKey),
    // The actor has taken ownership, even if a duplicate caller arrived first.
    Owned(PublicKey),
    Resolved {
        principal: PublicKey,
        selected: Connection,
    },
    Failed,
}

#[derive(Debug)]
pub(super) struct AuthenticatedConnection {
    record: Arc<ConnectionRecord>,
    // Only the creator can cancel an unpublished connection. Observers cannot.
    _unpublished: Option<UnpublishedConnection>,
}

#[derive(Debug)]
struct UnpublishedConnection {
    registry: Weak<Mutex<RegistryState>>,
    record: Arc<ConnectionRecord>,
}

pub(super) enum Admission {
    Owned(PublicKey),
    Resolved(PublicKey),
}

impl ConnectionRegistry {
    pub(super) async fn authenticate(
        &self,
        connection: Connection,
        authenticator: Option<&dyn ConnectionAuthenticator>,
    ) -> Result<AuthenticatedConnection, Error> {
        let (record, creator) = {
            let mut state = self.0.lock().expect("connection registry lock poisoned");
            if state.sealed {
                connection.close(0u32.into(), b"gossip is shut down");
                return Err(e!(Error::ActorDropped));
            }
            match state.connections.entry(connection.stable_id()) {
                std::collections::hash_map::Entry::Occupied(entry) => (entry.get().clone(), false),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let (state, _) = watch::channel(AdmissionState::Authenticating);
                    let record = Arc::new(ConnectionRecord { connection, state });
                    entry.insert(record.clone());
                    (record, true)
                }
            }
        };
        let unpublished = creator.then(|| UnpublishedConnection {
            registry: Arc::downgrade(&self.0),
            record: record.clone(),
        });
        if creator {
            let principal = match authenticator {
                Some(authenticator) => authenticator.authenticate(&record.connection).await?,
                None => record.connection.remote_id(),
            };
            record.state.send_if_modified(|state| {
                if matches!(state, AdmissionState::Authenticating) {
                    *state = AdmissionState::Verified(principal);
                    true
                } else {
                    false
                }
            });
        }
        let mut state = record.state.subscribe();
        loop {
            match &*state.borrow_and_update() {
                AdmissionState::Verified(_) | AdmissionState::Resolved { .. } => break,
                AdmissionState::Failed => return Err(e!(Error::ConnectionRejected)),
                AdmissionState::Authenticating | AdmissionState::Owned(_) => {}
            }
            state
                .changed()
                .await
                .map_err(|_| e!(Error::ConnectionRejected))?;
        }
        Ok(AuthenticatedConnection {
            record,
            _unpublished: unpublished,
        })
    }

    pub(super) fn get(&self, id: &ConnId) -> Option<Connection> {
        let record = self
            .0
            .lock()
            .expect("connection registry lock poisoned")
            .connections
            .get(id)
            .cloned()?;
        let state = record.state.borrow();
        match &*state {
            AdmissionState::Resolved { selected, .. } => Some(selected.clone()),
            _ => None,
        }
    }

    pub(super) fn principal(&self, connection: &Connection) -> Option<PublicKey> {
        let record = self
            .0
            .lock()
            .expect("connection registry lock poisoned")
            .connections
            .get(&connection.stable_id())
            .cloned()?;
        let state = record.state.borrow();
        match &*state {
            AdmissionState::Resolved { principal, .. } => Some(*principal),
            _ => None,
        }
    }

    pub(super) fn finish(
        &self,
        connection: &AuthenticatedConnection,
        result: &Result<Connection, Error>,
    ) {
        match result {
            Ok(selected) => {
                let newly_resolved = connection.record.state.send_if_modified(|state| {
                    if let AdmissionState::Owned(principal) = state {
                        *state = AdmissionState::Resolved {
                            principal: *principal,
                            selected: selected.clone(),
                        };
                        true
                    } else {
                        false
                    }
                });
                if newly_resolved && selected.stable_id() != connection.connection().stable_id() {
                    self.remove_record(&connection.record);
                }
            }
            Err(_) => {
                connection.record.fail(b"gossip connection not admitted");
                self.remove_record(&connection.record);
            }
        }
    }

    fn remove_record(&self, record: &Arc<ConnectionRecord>) {
        let mut state = self.0.lock().expect("connection registry lock poisoned");
        let id = record.connection.stable_id();
        if state
            .connections
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, record))
        {
            state.connections.remove(&id);
        }
    }

    pub(super) fn remove(&self, id: &ConnId) {
        let record = self
            .0
            .lock()
            .expect("connection registry lock poisoned")
            .connections
            .remove(id);
        if let Some(record) = record {
            record.fail(b"close from disconnect");
        }
    }

    pub(super) fn seal_and_close(&self) {
        let records = {
            let mut state = self.0.lock().expect("connection registry lock poisoned");
            state.sealed = true;
            std::mem::take(&mut state.connections)
        };
        for record in records.into_values() {
            record.fail(b"gossip is shut down");
        }
    }
}

impl AuthenticatedConnection {
    pub(super) fn connection(&self) -> &Connection {
        &self.record.connection
    }

    pub(super) fn claim(&self) -> Result<Admission, Error> {
        let mut result = Err(e!(Error::ConnectionRejected));
        self.record.state.send_modify(|state| match state {
            AdmissionState::Verified(principal) => {
                result = Ok(Admission::Owned(*principal));
                *state = AdmissionState::Owned(*principal);
            }
            AdmissionState::Resolved { principal, .. } => {
                result = Ok(Admission::Resolved(*principal))
            }
            _ => {}
        });
        result
    }
}

impl ConnectionRecord {
    fn fail(&self, reason: &'static [u8]) {
        self.connection.close(0u32.into(), reason);
        self.state.send_replace(AdmissionState::Failed);
    }
}

impl Drop for UnpublishedConnection {
    fn drop(&mut self) {
        let cancelled = self.record.state.send_if_modified(|state| {
            if matches!(
                state,
                AdmissionState::Authenticating | AdmissionState::Verified(_)
            ) {
                *state = AdmissionState::Failed;
                true
            } else {
                false
            }
        });
        if cancelled {
            self.record
                .connection
                .close(0u32.into(), b"gossip connection not admitted");
            if let Some(registry) = self.registry.upgrade() {
                ConnectionRegistry(registry).remove_record(&self.record);
            }
        }
    }
}
