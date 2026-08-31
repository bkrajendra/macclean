//! MacClean — Tauri desktop shell. All real work lives in `macclean-core`;
//! this crate only wires the IPC commands, event streaming and app state.

mod commands;
mod events;
mod state;

use state::AppState;
use tauri::Manager;
use tauri_plugin_log::{Target, TargetKind};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .targets([
                    Target::new(TargetKind::Stdout),
                    Target::new(TargetKind::LogDir {
                        file_name: Some("macclean".into()),
                    }),
                    Target::new(TargetKind::Webview),
                ])
                .build(),
        )
        .setup(|app| {
            app.manage(AppState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_system_info,
            commands::get_permission_status,
            commands::get_rules,
            commands::list_scopes,
            commands::start_scan,
            commands::cancel_scan,
            commands::get_scan_progress,
            commands::delete_selected,
            commands::reveal_in_finder,
            commands::open_privacy_settings,
            commands::restart_app,
        ])
        .run(tauri::generate_context!())
        .expect("error while running MacClean");
}
