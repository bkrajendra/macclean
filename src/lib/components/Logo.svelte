<script lang="ts">
	let { size = 40, class: klass = '' }: { size?: number; class?: string } = $props();
</script>

<img
	src="/app-icon.png"
	alt="MacClean"
	width={size}
	height={size}
	class="rounded-[22%] shadow-[0_8px_20px_-6px_rgb(124_92_252/0.55)] {klass}"
	style="width:{size}px;height:{size}px"
/>
