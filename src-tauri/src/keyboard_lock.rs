//! Clean Mode's system-wide keyboard lock: an active `CGEventTap` at the HID
//! level, running on its own thread for the app's lifetime.
//!
//! This deliberately does NOT use `rdev`: `rdev::grab` resolves a Unicode name
//! for every key press through the Text Input Source APIs
//! (`TISCopyCurrentKeyboardInputSource` / `TISGetInputSourceProperty`), which
//! assert they run on the main dispatch queue. Called from a tap thread, the
//! first key press aborted the whole app with `SIGTRAP`. The callback below
//! only reads the virtual keycode integer and never touches those APIs.

use core_foundation::base::TCFType;
use core_foundation::mach_port::CFMachPortRef;
use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use core_graphics::event::{
    CGEventTap, CGEventTapLocation, CGEventTapOptions, CGEventTapPlacement, CGEventType,
    CallbackResult, EventField,
};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

extern "C" {
    fn CGEventTapEnable(tap: CFMachPortRef, enable: bool);
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> bool;
}

/// Whether MacClean currently has Accessibility access — the permission
/// `spawn`'s event tap needs. A live, non-prompting check with no side
/// effects, so the UI can show accurate status before the user ever tries to
/// start Clean Mode (and after they grant it in System Settings, with no
/// relaunch needed for this check itself to reflect that).
pub fn is_trusted() -> bool {
    unsafe { AXIsProcessTrusted() }
}

/// Spawn the tap thread and wait until the tap is installed (or failed to be).
/// While `locked` is true every keyboard event is dropped system-wide and
/// `on_key` gets the key's name; while false every event passes untouched.
/// Mouse and trackpad events are never part of the tap's event mask.
pub fn spawn(
    locked: Arc<AtomicBool>,
    on_key: impl Fn(&'static str) + Send + 'static,
) -> Result<(), String> {
    let (tx, rx) = mpsc::channel::<Result<(), String>>();

    std::thread::Builder::new()
        .name("macclean-keyboard-lock".into())
        .spawn(move || {
            // The callback exists before the tap does, so it reaches the tap's
            // port through this pointer (set right after creation) to re-enable
            // it if macOS switches it off.
            let port = Arc::new(AtomicPtr::<c_void>::new(std::ptr::null_mut()));
            let port_in_cb = port.clone();

            let tap = CGEventTap::new(
                CGEventTapLocation::HID,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::Default,
                vec![
                    CGEventType::KeyDown,
                    CGEventType::KeyUp,
                    CGEventType::FlagsChanged,
                ],
                move |_proxy, etype, event| match etype {
                    // macOS disables a tap whose callback is ever too slow; a
                    // silently disabled tap would quietly unlock the keyboard.
                    CGEventType::TapDisabledByTimeout => {
                        let p = port_in_cb.load(Ordering::SeqCst);
                        if !p.is_null() {
                            unsafe { CGEventTapEnable(p as CFMachPortRef, true) };
                        }
                        CallbackResult::Keep
                    }
                    CGEventType::KeyDown | CGEventType::KeyUp | CGEventType::FlagsChanged => {
                        if !locked.load(Ordering::SeqCst) {
                            return CallbackResult::Keep;
                        }
                        if !matches!(etype, CGEventType::KeyUp) {
                            let code =
                                event.get_integer_value_field(EventField::KEYBOARD_EVENT_KEYCODE);
                            if let Some(name) = key_name(code) {
                                on_key(name);
                            }
                        }
                        CallbackResult::Drop
                    }
                    _ => CallbackResult::Keep,
                },
            );

            let tap =
                match tap {
                    Ok(tap) => tap,
                    Err(()) => {
                        let _ = tx.send(Err("Couldn't lock the keyboard — grant Accessibility \
                                         access for MacClean in System Settings, then try again."
                            .into()));
                        return;
                    }
                };
            port.store(
                tap.mach_port().as_concrete_TypeRef() as *mut c_void,
                Ordering::SeqCst,
            );
            let Ok(source) = tap.mach_port().create_runloop_source(0) else {
                let _ = tx.send(Err(
                    "Couldn't attach the keyboard lock to its run loop.".into()
                ));
                return;
            };
            CFRunLoop::get_current().add_source(&source, unsafe { kCFRunLoopCommonModes });
            tap.enable();
            let _ = tx.send(Ok(()));
            CFRunLoop::run_current();
        })
        .map_err(|e| e.to_string())?;

    rx.recv_timeout(Duration::from_secs(5))
        .map_err(|_| "Timed out starting the keyboard lock.".to_string())?
}

/// macOS virtual keycode → the names `KeyboardMap.svelte` lays out.
fn key_name(code: i64) -> Option<&'static str> {
    Some(match code {
        0 => "KeyA",
        1 => "KeyS",
        2 => "KeyD",
        3 => "KeyF",
        4 => "KeyH",
        5 => "KeyG",
        6 => "KeyZ",
        7 => "KeyX",
        8 => "KeyC",
        9 => "KeyV",
        11 => "KeyB",
        12 => "KeyQ",
        13 => "KeyW",
        14 => "KeyE",
        15 => "KeyR",
        16 => "KeyY",
        17 => "KeyT",
        18 => "Num1",
        19 => "Num2",
        20 => "Num3",
        21 => "Num4",
        22 => "Num6",
        23 => "Num5",
        24 => "Equal",
        25 => "Num9",
        26 => "Num7",
        27 => "Minus",
        28 => "Num8",
        29 => "Num0",
        30 => "RightBracket",
        31 => "KeyO",
        32 => "KeyU",
        33 => "LeftBracket",
        34 => "KeyI",
        35 => "KeyP",
        36 => "Return",
        37 => "KeyL",
        38 => "KeyJ",
        39 => "Quote",
        40 => "KeyK",
        41 => "SemiColon",
        42 => "BackSlash",
        43 => "Comma",
        44 => "Slash",
        45 => "KeyN",
        46 => "KeyM",
        47 => "Dot",
        48 => "Tab",
        49 => "Space",
        50 => "BackQuote",
        51 => "Backspace",
        53 => "Escape",
        54 => "MetaRight",
        55 => "MetaLeft",
        56 => "ShiftLeft",
        57 => "CapsLock",
        58 => "Alt",
        59 => "ControlLeft",
        60 => "ShiftRight",
        61 => "AltGr",
        62 => "ControlRight",
        96 => "F5",
        97 => "F6",
        98 => "F7",
        99 => "F3",
        100 => "F8",
        101 => "F9",
        103 => "F11",
        109 => "F10",
        111 => "F12",
        118 => "F4",
        120 => "F2",
        122 => "F1",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::key_name;

    #[test]
    fn maps_keycodes_to_keyboard_map_names() {
        assert_eq!(key_name(0), Some("KeyA"));
        assert_eq!(key_name(49), Some("Space"));
        assert_eq!(key_name(55), Some("MetaLeft"));
        assert_eq!(key_name(122), Some("F1"));
        assert_eq!(key_name(10), None);
    }
}
