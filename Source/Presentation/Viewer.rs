// SPDX-License-Identifier: MIT
// One viewer session delegates presentation while the browser retains its client and authority checks.
use crate::{markup, page_view, reader};
use anyhow::{Result, ensure};

pub enum Session {
    Terminal(Box<reader::Session>),
    #[cfg(feature = "gui")]
    Graphical(crate::graphical::Session),
}

/// Create the presentation before its workflow starts any network operation.
pub fn run(
    gui: bool,
    tui: bool,
    ascii: bool,
    work: impl FnOnce(Session) -> Result<()> + Send + 'static,
) -> Result<()> {
    ensure!(!(gui && tui), "--gui and --tui cannot be combined");
    if gui {
        #[cfg(feature = "gui")]
        {
            return crate::graphical::run(work);
        }
        #[cfg(not(feature = "gui"))]
        {
            anyhow::bail!("graphical viewing requires HyperNetSuite built with the gui feature");
        }
    }
    work(Session::Terminal(Box::new(reader::Session::new(
        tui, ascii,
    )?)))
}

impl Session {
    pub fn configure_graphics(&self, options: &crate::terminal_graphics::Options) -> Result<()> {
        match self {
            Self::Terminal(session) => session.configure_graphics(options),
            #[cfg(feature = "gui")]
            Self::Graphical(session) => session.configure_graphics(options),
        }
    }
    pub fn install_image(
        &self,
        asset: &markup::media::Asset,
        pixels: crate::media_import::Pixels,
    ) -> Result<()> {
        match self {
            Self::Terminal(session) => session.install_image(asset, pixels),
            #[cfg(feature = "gui")]
            Self::Graphical(session) => session.install_image(asset, pixels),
        }
    }
    pub fn confirm_form(&self, review: &impl serde::Serialize) -> Result<Option<bool>> {
        ensure!(
            self.interactive(),
            "form confirmation requires an interactive viewer"
        );
        match self {
            Self::Terminal(session) => session.confirm_form(review),
            #[cfg(feature = "gui")]
            Self::Graphical(session) => session.confirm_form(review),
        }
    }
    pub fn interactive(&self) -> bool {
        match self {
            Self::Terminal(session) => session.interactive(),
            #[cfg(feature = "gui")]
            Self::Graphical(session) => session.interactive(),
        }
    }
    pub fn preflight(&self, document: &markup::Document, view: &page_view::View) -> Result<()> {
        match self {
            Self::Terminal(session) => session.preflight(document, view),
            #[cfg(feature = "gui")]
            Self::Graphical(session) => session.preflight(document, view),
        }
    }
    pub fn request<T, F>(&self, operation: F) -> Result<Option<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        match self {
            Self::Terminal(session) => session.request(operation),
            #[cfg(feature = "gui")]
            Self::Graphical(session) => session.request(operation),
        }
    }
    pub fn show(
        &self,
        document: &markup::Document,
        metadata: &[String],
        view: &mut page_view::View,
        status: &str,
        mode: reader::Mode,
    ) -> Result<reader::Action> {
        match self {
            Self::Terminal(session) => session.show(document, metadata, view, status, mode),
            #[cfg(feature = "gui")]
            Self::Graphical(session) => session.show(document, metadata, view, status, mode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_viewer_delegates_requests_and_refuses_noninteractive_confirmation() {
        run(false, false, false, |session| {
            assert!(!session.interactive());
            assert_eq!(session.request(|| Ok(17))?, Some(17));
            assert!(
                session
                    .confirm_form(&serde_json::json!({"submission":"Exact"}))
                    .is_err()
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn conflicting_viewers_never_start_the_workflow() {
        assert!(
            run(true, true, false, |_| panic!(
                "conflicting viewer started work"
            ))
            .is_err()
        );
    }

    #[cfg(not(feature = "gui"))]
    #[test]
    fn unavailable_graphical_viewer_never_starts_the_workflow() {
        let error = run(true, false, false, |_| {
            panic!("unavailable viewer started work")
        })
        .unwrap_err();
        assert!(error.to_string().contains("gui feature"));
    }
}
