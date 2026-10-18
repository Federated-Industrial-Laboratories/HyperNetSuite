// SPDX-License-Identifier: MIT
// Bounded presentation messages keep browser operations outside the native event loop.
use super::*;
use std::sync::mpsc::{SyncSender, sync_channel};

pub(super) enum Message {
    Page(Box<Page>),
    Image(
        markup::media::Asset,
        crate::media_import::Pixels,
        SyncSender<Result<()>>,
    ),
    Confirm(serde_json::Value, SyncSender<bool>),
    Busy,
    Finished(Result<(), String>),
}

pub(super) struct Page {
    pub document: markup::Document,
    pub metadata: Vec<String>,
    pub view: page_view::View,
    pub status: String,
    pub mode: reader::Mode,
    pub reply: Option<SyncSender<(reader::Action, page_view::View)>>,
}

pub struct Session {
    pub(super) sender: SyncSender<Message>,
    pub(super) context: egui::Context,
    pub(super) closed: Arc<AtomicBool>,
}

impl Session {
    fn send(&self, message: Message) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let sent = self.sender.send(message).is_ok();
        self.context.request_repaint();
        sent
    }

    pub fn interactive(&self) -> bool {
        true
    }

    pub fn configure_graphics(&self, options: &crate::terminal_graphics::Options) -> Result<()> {
        options.validate()
    }

    pub fn preflight(&self, document: &markup::Document, _: &page_view::View) -> Result<()> {
        markup::media::validate_assets(&document.assets).map_err(anyhow::Error::msg)
    }

    pub fn request<T, F>(&self, operation: F) -> Result<Option<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        if !self.send(Message::Busy) {
            return Ok(None);
        }
        let result = operation();
        if self.closed.load(Ordering::Acquire) {
            return Ok(None);
        }
        result.map(Some)
    }

    pub fn install_image(
        &self,
        asset: &markup::media::Asset,
        pixels: crate::media_import::Pixels,
    ) -> Result<()> {
        pixels.validate()?;
        ensure!(
            asset.width == pixels.width && asset.height == pixels.height,
            "media dimensions differ from manifest"
        );
        let (sender, receiver) = sync_channel(1);
        if !self.send(Message::Image(asset.clone(), pixels, sender)) {
            return Ok(());
        }
        receiver.recv().unwrap_or(Ok(()))
    }

    pub fn confirm_form(&self, review: &impl serde::Serialize) -> Result<Option<bool>> {
        let bytes = serde_json::to_vec(review)?;
        ensure!(bytes.len() <= 32_768, "form review exceeds display limit");
        let value = serde_json::from_slice(&bytes)?;
        let (sender, receiver) = sync_channel(1);
        if !self.send(Message::Confirm(value, sender)) {
            return Ok(None);
        }
        Ok(receiver.recv().ok())
    }

    pub fn show(
        &self,
        document: &markup::Document,
        metadata: &[String],
        view: &mut page_view::View,
        status: &str,
        mode: reader::Mode,
    ) -> Result<reader::Action> {
        self.preflight(document, view)?;
        let (sender, receiver) = sync_channel(1);
        let page = Page {
            document: document.clone(),
            metadata: metadata.to_vec(),
            view: view.clone(),
            status: status.to_owned(),
            mode,
            reply: Some(sender),
        };
        if !self.send(Message::Page(Box::new(page))) {
            return Ok(reader::Action::Quit);
        }
        match receiver.recv() {
            Ok((action, updated)) => {
                *view = updated;
                Ok(action)
            }
            Err(_) => Ok(reader::Action::Quit),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> (Session, Receiver<Message>) {
        let (sender, receiver) = sync_channel(1);
        (
            Session {
                sender,
                context: egui::Context::default(),
                closed: Arc::new(AtomicBool::new(false)),
            },
            receiver,
        )
    }

    #[test]
    fn closing_confirmation_never_confirms_a_submission() {
        let (session, receiver) = session();
        let worker = std::thread::spawn(move || {
            session.confirm_form(&serde_json::json!({"recipientAddress":"ExactRecipient"}))
        });
        let Message::Confirm(value, reply) = receiver.recv().unwrap() else {
            panic!("expected review");
        };
        assert_eq!(value["recipientAddress"], "ExactRecipient");
        drop(reply);
        assert_eq!(worker.join().unwrap().unwrap(), None);
    }

    #[test]
    fn closed_window_prevents_new_network_work() {
        let (session, _receiver) = session();
        session.closed.store(true, Ordering::Release);
        assert!(
            session
                .request::<(), _>(|| panic!("network operation after close"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn oversized_review_is_refused_before_delivery() {
        let (session, receiver) = session();
        assert!(session.confirm_form(&"x".repeat(32769)).is_err());
        assert!(receiver.try_recv().is_err());
    }
}
