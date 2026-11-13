// SPDX-License-Identifier: MIT
// A private launcher supplies navigation; publisher content cannot obtain this channel.
use super::*;
use std::{cell::RefCell, collections::VecDeque, marker::PhantomData, rc::Rc, sync::Mutex};
const CAPACITY: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NavigationError {
    Invalid,
    Full,
    Closed,
}
struct Shared {
    attached: AtomicBool,
    context: Mutex<Option<egui::Context>>,
}
#[derive(Clone)]
pub struct NavigationSender {
    sender: SyncSender<Option<String>>,
    shared: Arc<Shared>,
}
pub struct NavigationInbox {
    receiver: Receiver<Option<String>>,
    pending: VecDeque<String>,
    shared: Arc<Shared>,
}
pub fn navigation_channel() -> (NavigationSender, NavigationInbox) {
    let (sender, receiver) = sync_channel(CAPACITY);
    let shared = Arc::new(Shared {
        attached: AtomicBool::new(false),
        context: Mutex::new(None),
    });
    (
        NavigationSender {
            sender,
            shared: shared.clone(),
        },
        NavigationInbox {
            receiver,
            pending: VecDeque::new(),
            shared,
        },
    )
}
fn valid(location: &str) -> bool {
    location.len() <= 512
        && location.starts_with("hypernet://")
        && location.bytes().all(|b| (33..127).contains(&b))
        && markup::parse(&format!(
            "{}\n# Address\n=> {location} Open\n",
            markup::PROFILE
        ))
        .is_ok()
}
impl NavigationSender {
    pub fn try_open(&self, location: Option<String>) -> std::result::Result<(), NavigationError> {
        if location.as_deref().is_some_and(|s| !valid(s)) {
            return Err(NavigationError::Invalid);
        }
        self.sender.try_send(location).map_err(|e| match e {
            std::sync::mpsc::TrySendError::Full(_) => NavigationError::Full,
            std::sync::mpsc::TrySendError::Disconnected(_) => NavigationError::Closed,
        })?;
        if let Ok(context) = self.shared.context.lock()
            && let Some(context) = context.as_ref()
        {
            context.request_repaint();
        }
        Ok(())
    }
    pub fn is_attached(&self) -> bool {
        self.shared.attached.load(Ordering::Acquire)
    }
}
impl NavigationInbox {
    pub(super) fn attach(&self, context: &egui::Context) {
        if let Ok(mut saved) = self.shared.context.lock() {
            *saved = Some(context.clone());
        }
        self.shared.attached.store(true, Ordering::Release);
    }
    pub(super) fn poll(&mut self, context: &egui::Context) {
        let mut focus = false;
        // Eight in-flight commands plus eight deferred links. Never discard accepted links.
        for _ in 0..CAPACITY {
            if self.pending.len() == CAPACITY {
                break;
            }
            match self.receiver.try_recv() {
                Ok(location) => {
                    focus = true;
                    if let Some(location) = location {
                        self.pending.push_back(location);
                    }
                }
                Err(_) => break,
            }
        }
        if focus {
            context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            context.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            context.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
    }
    pub(super) fn queued(&self) -> usize {
        self.pending.len()
    }
    pub(super) fn next(&mut self) -> Option<String> {
        self.pending.pop_front()
    }
}
impl Drop for NavigationInbox {
    fn drop(&mut self) {
        self.shared.attached.store(false, Ordering::Release);
        if let Ok(mut context) = self.shared.context.lock() {
            *context = None;
        }
    }
}
struct Registered {
    id: u64,
    inbox: Option<NavigationInbox>,
}
thread_local! {
    static REGISTERED:RefCell<Option<Registered>>=const{RefCell::new(None)};
    static NEXT:std::cell::Cell<u64>=const{std::cell::Cell::new(1)};
}
/// The guard stays on the installing thread until the normal browse dispatch returns.
pub struct NavigationRegistration {
    id: u64,
    _main_thread: PhantomData<Rc<()>>,
}
pub fn install_navigation(inbox: NavigationInbox) -> Result<NavigationRegistration> {
    REGISTERED.with(|slot| {
        let mut slot = slot.borrow_mut();
        ensure!(slot.is_none(), "a navigation channel is already installed");
        let id = NEXT.with(|next| {
            let id = next.get();
            next.set(
                id.checked_add(1)
                    .expect("navigation registration exhausted"),
            );
            id
        });
        *slot = Some(Registered {
            id,
            inbox: Some(inbox),
        });
        Ok(NavigationRegistration {
            id,
            _main_thread: PhantomData,
        })
    })
}
pub(super) fn take_registered() -> Option<NavigationInbox> {
    REGISTERED.with(|slot| slot.borrow_mut().as_mut().and_then(|r| r.inbox.take()))
}
impl Drop for NavigationRegistration {
    fn drop(&mut self) {
        REGISTERED.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().is_some_and(|r| r.id == self.id) {
                *slot = None;
            }
        });
    }
}
#[cfg(test)]
#[path = "../../Tests/Unit/Graphical/NavigationUnitTests.rs"]
mod tests;
