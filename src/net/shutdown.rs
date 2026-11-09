//! The original shutdown operation retains its request, join and terminal result.

use std::{future::Future, pin::Pin, sync::Arc};

use n0_error::e;
use n0_future::task::AbortOnDropHandle;
use tokio::sync::{mpsc, oneshot, Mutex};

use super::{Actor, Error, LocalActorMessage};

#[derive(derive_more::Debug)]
pub(super) enum GossipShutdown {
    Running(AbortOnDropHandle<()>),
    // Retain this exact operation if its observer is cancelled after sending
    // the request or joining the task. A later observer must not send again.
    Draining(#[debug(skip)] Pin<Box<dyn Future<Output = ShutdownOutcome> + Send>>),
    Complete(ShutdownOutcome),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ShutdownOutcome {
    Success,
    ActorDropped,
}

impl GossipShutdown {
    pub(super) async fn finish(
        &mut self,
        local_tx: &mpsc::Sender<LocalActorMessage>,
        actor: &Arc<Mutex<Option<Actor>>>,
    ) -> Result<(), Error> {
        if matches!(self, Self::Running(_)) {
            let Self::Running(handle) =
                std::mem::replace(self, Self::Complete(ShutdownOutcome::ActorDropped))
            else {
                unreachable!("running shutdown owns the actor handle")
            };
            *self = Self::Draining(Box::pin(drain(handle, local_tx.clone(), actor.clone())));
        }
        let outcome = match self {
            Self::Draining(future) => future.await,
            Self::Complete(outcome) => *outcome,
            Self::Running(_) => unreachable!("shutdown was started above"),
        };
        *self = Self::Complete(outcome);
        match outcome {
            ShutdownOutcome::Success => Ok(()),
            ShutdownOutcome::ActorDropped => Err(e!(Error::ActorDropped)),
        }
    }
}

async fn drain(
    mut handle: AbortOnDropHandle<()>,
    local_tx: mpsc::Sender<LocalActorMessage>,
    actor: Arc<Mutex<Option<Actor>>>,
) -> ShutdownOutcome {
    let request = async {
        let (reply, reply_rx) = oneshot::channel();
        local_tx.send(LocalActorMessage::Shutdown { reply }).await?;
        reply_rx.await?;
        Ok::<_, Error>(())
    };
    tokio::pin!(request);
    // An abnormal task exit may leave a full receiver alive in its owner.
    // Request backpressure must not hide completion of the original task.
    let (request_result, task_result) = tokio::select! {
        biased;
        result = &mut request => (Some(result), (&mut handle).await),
        result = &mut handle => (None, result),
    };
    // The retained operation also owns recovery cleanup after a panic or abort.
    let mut actor = actor.lock().await;
    if let Some(actor) = actor.as_mut() {
        actor.shutdown_tasks().await;
    }
    drop(actor.take());
    let request_result = match request_result {
        Some(result) => result,
        None => request.await,
    };
    if request_result.is_ok() && task_result.is_ok() {
        ShutdownOutcome::Success
    } else {
        ShutdownOutcome::ActorDropped
    }
}
