import '@testing-library/jest-dom/vitest';

// jsdom has no Web Animations API; Svelte transitions call element.animate().
if (!Element.prototype.animate) {
	Element.prototype.animate = function () {
		const anim = {
			finished: Promise.resolve(),
			onfinish: null as null | (() => void),
			cancel() {},
			finish() {},
			currentTime: 0
		};
		queueMicrotask(() => anim.onfinish?.());
		return anim as unknown as Animation;
	};
}
