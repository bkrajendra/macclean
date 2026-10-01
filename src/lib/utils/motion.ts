import type { TransitionConfig } from 'svelte/transition';

/** Mirrors --ease-out in app.css: cubic-bezier(0.23, 1, 0.32, 1). */
const [X1, Y1, X2, Y2] = [0.23, 1, 0.32, 1];
const bezier = (p1: number, p2: number, u: number) =>
	3 * p1 * u * (1 - u) ** 2 + 3 * p2 * u ** 2 * (1 - u) + u ** 3;
const bezierSlope = (p1: number, p2: number, u: number) =>
	3 * (1 - u) ** 2 * p1 + 6 * (1 - u) * u * (p2 - p1) + 3 * u ** 2 * (1 - p2);

export function easeOut(t: number): number {
	let u = t;
	for (let i = 0; i < 8; i++) {
		const err = bezier(X1, X2, u) - t;
		const slope = bezierSlope(X1, X2, u);
		if (Math.abs(err) < 1e-4 || slope === 0) break;
		u -= err / slope;
	}
	return bezier(Y1, Y2, Math.min(1, Math.max(0, u)));
}

export const prefersReducedMotion = () =>
	typeof window !== 'undefined' &&
	!!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

interface PopParams {
	/** Starting scale; never 0. */
	start?: number;
	/** Starting translateY in px. */
	y?: number;
	duration?: number;
	delay?: number;
}

/** Fade + small scale/rise. Interruptible; drops movement under reduced motion. */
export function pop(
	_node: Element,
	{ start = 0.96, y = 0, duration = 180, delay = 0 }: PopParams = {}
): TransitionConfig {
	const reduce = prefersReducedMotion();
	return {
		delay,
		duration: reduce ? Math.min(duration, 120) : duration,
		easing: easeOut,
		css: (t, u) =>
			reduce
				? `opacity:${t}`
				: `opacity:${t};transform:translateY(${y * u}px) scale(${start + (1 - start) * t})`
	};
}
