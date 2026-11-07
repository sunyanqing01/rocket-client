mod vpn;

use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Runtime, State};

/// Set once the window has finished its start-up resize dance. Before that,
/// `Resized` events fire while Windows is still creating the window and would
/// hide it for good.
static TRAY_READY: AtomicBool = AtomicBool::new(false);

struct AppState {
    session: Mutex<Option<vpn::Session>>,
}

#[tauri::command]
fn vpn_connect(
    config: vpn::ConnectConfig,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<vpn::ConnectResult, String> {
    let mut guard = state.session.lock().map_err(|_| "内部状态异常".to_string())?;
    if guard.is_some() {
        return Err("已经处于连接状态，请先断开".into());
    }

    let lg = app.clone();
    let emit_log = move |m: &str| {
        let _ = lg.emit("vpn-log", m.to_string());
    };

    let (sess, res) = vpn::connect(&config, emit_log)?;
    *guard = Some(sess);

    let _ = app.emit(
        "vpn-state",
        serde_json::json!({ "connected": true, "vip": res.vip }),
    );
    Ok(res)
}

#[tauri::command]
fn vpn_disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(|_| "内部状态异常".to_string())?;
    if let Some(s) = guard.take() {
        s.stop();
        drop(s);
        let _ = app.emit("vpn-log", "已断开，路由已清理");
        let _ = app.emit("vpn-state", serde_json::json!({ "connected": false }));
    } else {
        let _ = app.emit("vpn-log", "当前未连接");
    }
    Ok(())
}

#[tauri::command]
fn local_mac() -> String {
    vpn::local_mac()
}

#[tauri::command]
fn is_elevated() -> bool {
    // The exe now carries a requireAdministrator manifest, so this is always
    // true in release; kept so the UI can still warn in a dev run.
    std::process::Command::new("net")
        .arg("session")
        .creation_flags(0x0800_0000)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Bring the main window back from the tray.
fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Quit cleanly: tear the tunnel down so no routes are left behind.
fn quit_app<R: Runtime>(app: &AppHandle<R>) {
    if let Some(state) = app.try_state::<AppState>() {
        if let Ok(mut g) = state.session.lock() {
            if let Some(s) = g.take() {
                s.stop();
            }
        }
    }
    app.exit(0);
}

fn build_tray<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "打开主界面", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    let mut builder = TrayIconBuilder::with_id("main")
        .tooltip("Rocket Client")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "quit" => quit_app(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });

    // Fall back to the bundled PNG if the window icon is unavailable.
    let icon = match app.default_window_icon() {
        Some(i) => Some(i.clone()),
        None => tauri::image::Image::from_bytes(include_bytes!("../icons/32x32.png")).ok(),
    };
    if let Some(icon) = icon {
        builder = builder.icon(icon);
    }

    builder.build(app)?;
    Ok(())
}

/// A GUI process has no console, so a panic (e.g. WebView2 refusing to start)
/// would otherwise vanish without a trace. Keep a short log in %TEMP% instead.
fn install_panic_logger() {
    std::panic::set_hook(Box::new(|info| {
        use std::io::Write;
        let path = std::env::temp_dir().join("rocket-crash.log");
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = writeln!(f, "[{ts}] {info}");
        }
    }));
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    install_panic_logger();
    tauri::Builder::default()
        // Must be registered first. Without it a second launch would build a
        // second WebView2 against the same user-data folder, fail, and exit
        // silently — which looks like "double-clicking the shortcut does
        // nothing".
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main(app);
        }))
        .manage(AppState { session: Mutex::new(None) })
        .invoke_handler(tauri::generate_handler![
            vpn_connect,
            vpn_disconnect,
            local_mac,
            is_elevated
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            build_tray(&handle)?;
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                TRAY_READY.store(true, Ordering::SeqCst);
            });
            Ok(())
        })
        .on_window_event(|window, event| match event {
            // Closing the window keeps the tunnel alive in the tray.
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = window.hide();
            }
            // Minimizing also drops the window into the tray. Ignored until the
            // window is fully up, otherwise the start-up resize hides it.
            tauri::WindowEvent::Resized(_) => {
                if TRAY_READY.load(Ordering::SeqCst) && window.is_minimized().unwrap_or(false) {
                    let _ = window.hide();
                }
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("error while running Rocket Client");
}
