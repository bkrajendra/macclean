<script lang="ts">
	/**
	 * A rough physical layout of a Mac keyboard, keyed by `rdev::Key`'s Debug
	 * name (see `src-tauri/src/commands.rs::toggle_keyboard_lock`). Purely a
	 * decorative "which key was just wiped" indicator — not meant to be a
	 * pixel-accurate keyboard.
	 */
	let { activeKey = null }: { activeKey?: string | null } = $props();

	interface KeyDef {
		id: string;
		label: string;
		flex?: number;
	}

	const row = (...keys: KeyDef[]) => keys;
	const k = (id: string, label: string, flex = 1): KeyDef => ({ id, label, flex });

	const rows: KeyDef[][] = [
		row(
			k('Escape', 'esc'),
			k('F1', 'F1'),
			k('F2', 'F2'),
			k('F3', 'F3'),
			k('F4', 'F4'),
			k('F5', 'F5'),
			k('F6', 'F6'),
			k('F7', 'F7'),
			k('F8', 'F8'),
			k('F9', 'F9'),
			k('F10', 'F10'),
			k('F11', 'F11'),
			k('F12', 'F12')
		),
		row(
			k('BackQuote', '`'),
			k('Num1', '1'),
			k('Num2', '2'),
			k('Num3', '3'),
			k('Num4', '4'),
			k('Num5', '5'),
			k('Num6', '6'),
			k('Num7', '7'),
			k('Num8', '8'),
			k('Num9', '9'),
			k('Num0', '0'),
			k('Minus', '-'),
			k('Equal', '='),
			k('Backspace', 'delete', 1.7)
		),
		row(
			k('Tab', 'tab', 1.5),
			k('KeyQ', 'Q'),
			k('KeyW', 'W'),
			k('KeyE', 'E'),
			k('KeyR', 'R'),
			k('KeyT', 'T'),
			k('KeyY', 'Y'),
			k('KeyU', 'U'),
			k('KeyI', 'I'),
			k('KeyO', 'O'),
			k('KeyP', 'P'),
			k('LeftBracket', '['),
			k('RightBracket', ']'),
			k('BackSlash', '\\', 1.2)
		),
		row(
			k('CapsLock', 'caps', 1.8),
			k('KeyA', 'A'),
			k('KeyS', 'S'),
			k('KeyD', 'D'),
			k('KeyF', 'F'),
			k('KeyG', 'G'),
			k('KeyH', 'H'),
			k('KeyJ', 'J'),
			k('KeyK', 'K'),
			k('KeyL', 'L'),
			k('SemiColon', ';'),
			k('Quote', "'"),
			k('Return', 'return', 1.9)
		),
		row(
			k('ShiftLeft', 'shift', 2.3),
			k('KeyZ', 'Z'),
			k('KeyX', 'X'),
			k('KeyC', 'C'),
			k('KeyV', 'V'),
			k('KeyB', 'B'),
			k('KeyN', 'N'),
			k('KeyM', 'M'),
			k('Comma', ','),
			k('Dot', '.'),
			k('Slash', '/'),
			k('ShiftRight', 'shift', 2.3)
		),
		row(
			k('ControlLeft', 'ctrl', 1.3),
			k('Alt', 'opt', 1.1),
			k('MetaLeft', 'cmd', 1.3),
			k('Space', '', 5.5),
			k('MetaRight', 'cmd', 1.3),
			k('AltGr', 'opt', 1.1),
			k('ControlRight', 'ctrl', 1.3)
		)
	];
</script>

<div class="mx-auto flex w-full max-w-3xl flex-col gap-1.5 select-none" aria-hidden="true">
	{#each rows as cols, i (i)}
		<div class="flex gap-1.5">
			{#each cols as key (key.id)}
				<div
					class="flex h-9 items-center justify-center rounded-md border text-[0.65rem] font-medium uppercase tracking-wide transition-all duration-150 sm:h-11 sm:text-xs {activeKey ===
					key.id
						? 'scale-95 border-brand-2/70 bg-brand-2/80 text-white shadow-[0_0_16px_2px_rgb(168_85_247/0.55)]'
						: 'border-white/10 bg-white/[0.05] text-white/50'}"
					style="flex: {key.flex ?? 1}"
				>
					{key.label}
				</div>
			{/each}
		</div>
	{/each}
</div>
