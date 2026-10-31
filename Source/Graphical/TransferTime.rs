// SPDX-License-Identifier: MIT
// Human duration controls produce one fixed absolute expiry for reviewed transfer operations.
use crate::authority_domains::transfer::MAXIMUM_LIFETIME_MS;
use anyhow::{Context, Result, ensure};
use eframe::egui;
#[derive(Clone, Copy, PartialEq)]
enum Unit {
    Minutes,
    Hours,
    Days,
}
impl Unit {
    fn milliseconds(self) -> u64 {
        match self {
            Self::Minutes => 60_000,
            Self::Hours => 3_600_000,
            Self::Days => 86_400_000,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Minutes => "minutes",
            Self::Hours => "hours",
            Self::Days => "days",
        }
    }
}
pub(super) struct Duration {
    amount: u64,
    unit: Unit,
}
impl Default for Duration {
    fn default() -> Self {
        Self {
            amount: 24,
            unit: Unit::Hours,
        }
    }
}
impl Duration {
    pub(super) fn control(&mut self, ui: &mut egui::Ui, id: &'static str, label: &str) {
        ui.horizontal(|ui| {
            let label = ui.label(label);
            let response = ui
                .add(
                    egui::DragValue::new(&mut self.amount)
                        .range(1..=MAXIMUM_LIFETIME_MS / self.unit.milliseconds()),
                )
                .labelled_by(label.id);
            super::super::scrolling::reveal_focus(&response);
            egui::ComboBox::from_id_salt(id)
                .selected_text(self.unit.label())
                .show_ui(ui, |ui| {
                    for unit in [Unit::Minutes, Unit::Hours, Unit::Days] {
                        ui.selectable_value(&mut self.unit, unit, unit.label());
                    }
                });
        });
        self.amount = self
            .amount
            .clamp(1, MAXIMUM_LIFETIME_MS / self.unit.milliseconds());
    }
    pub(super) fn expiry(&self, now: u64) -> Result<u64> {
        let duration = self
            .amount
            .checked_mul(self.unit.milliseconds())
            .context("duration overflow")?;
        ensure!(
            duration > 1250 && duration <= MAXIMUM_LIFETIME_MS,
            "choose a duration within seven days"
        );
        now.checked_add(duration).context("expiry overflow")
    }
}
pub(super) fn now() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}
pub(super) fn acceptance(
    now: u64,
    offer: u64,
    host_lifetime: u64,
    shorter: Option<u64>,
) -> Result<u64> {
    let limit = offer.min(now.saturating_add(host_lifetime));
    let expiry = shorter.unwrap_or(limit);
    ensure!(
        expiry <= limit,
        "shorter duration exceeds the offer or selected store lifetime"
    );
    ensure!(
        now.checked_add(1250).is_some_and(|time| time < expiry),
        "offer or selected store lifetime has expired"
    );
    Ok(expiry)
}
pub(super) fn duration(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    if seconds >= 86_400 {
        format!("{}d {}h", seconds / 86_400, seconds % 86_400 / 3600)
    } else if seconds >= 3600 {
        format!("{}h {}m", seconds / 3600, seconds % 3600 / 60)
    } else if seconds >= 60 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}
pub(super) fn utc(milliseconds: u64) -> String {
    let Ok(seconds) = libc::time_t::try_from(milliseconds / 1000) else {
        return "Invalid expiry".into();
    };
    let mut time: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&seconds, &mut time) }.is_null() {
        return "Invalid expiry".into();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} UTC",
        time.tm_year + 1900,
        time.tm_mon + 1,
        time.tm_mday,
        time.tm_hour,
        time.tm_min,
        time.tm_sec,
        milliseconds % 1000
    )
}
pub(super) fn field(ui: &mut egui::Ui, label: &str, expiry: u64) {
    let remaining = now().map_or_else(
        |_| "Clock unavailable".into(),
        |now| {
            if expiry > now {
                format!("In {}", duration(expiry - now))
            } else {
                "Expired".into()
            }
        },
    );
    ui.label(egui::RichText::new(label).strong());
    ui.label(remaining)
        .on_hover_text(format!("{}\nUnix milliseconds: {expiry}", utc(expiry)));
    ui.add_space(5.0);
}
#[cfg(test)]
#[path = "../../Tests/Unit/Graphical/TransferTimeUnitTests.rs"]
mod tests;
