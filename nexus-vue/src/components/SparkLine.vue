<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{
  data: number[];
  color?: string;
  min?: number;
  max?: number;
  height?: number;
}>();

const W = 400;
const FIXED = 60;
const H = computed(() => props.height ?? 56);
const clr = computed(() => props.color ?? '#3b82f6');
const uid = Math.random().toString(36).slice(2);

const padded = computed<number[]>(() => {
  const d = props.data;
  if (!d.length) return new Array(FIXED).fill(0);
  if (d.length >= FIXED) return d.slice(-FIXED);
  return [...new Array(FIXED - d.length).fill(d[0]), ...d];
});

const pts = computed<[number, number][]>(() => {
  const d = padded.value;
  const lo = props.min ?? Math.min(...d);
  const hi = props.max ?? Math.max(...d);
  const rng = hi - lo || 1;
  const pad = H.value * 0.08;
  const inn = H.value - pad * 2;
  return d.map((v, i) => [(i / (FIXED - 1)) * W, pad + inn - ((v - lo) / rng) * inn]);
});

function smooth(pts: [number, number][], close = false): string {
  if (!pts.length) return '';
  let d = `M ${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
  for (let i = 1; i < pts.length; i++) {
    const p0 = pts[Math.max(i - 2, 0)];
    const p1 = pts[i - 1];
    const p2 = pts[i];
    const p3 = pts[Math.min(i + 1, pts.length - 1)];
    const cp1x = p1[0] + (p2[0] - p0[0]) / 6;
    const cp1y = p1[1] + (p2[1] - p0[1]) / 6;
    const cp2x = p2[0] - (p3[0] - p1[0]) / 6;
    const cp2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2[0].toFixed(1)} ${p2[1].toFixed(1)}`;
  }
  if (close && pts.length > 1) {
    const last = pts[pts.length - 1];
    d += ` L ${last[0].toFixed(1)} ${H.value} L ${pts[0][0].toFixed(1)} ${H.value} Z`;
  }
  return d;
}

const linePath = computed(() => smooth(pts.value));
const areaPath = computed(() => smooth(pts.value, true));
const lastPt = computed(() => pts.value[pts.value.length - 1]);
</script>

<template>
  <svg :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" class="w-full" :style="{ height: `${H}px` }">
    <defs>
      <linearGradient :id="uid" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" :stop-color="clr" stop-opacity="0.25" />
        <stop offset="100%" :stop-color="clr" stop-opacity="0.02" />
      </linearGradient>
    </defs>
    <path :d="areaPath" :fill="`url(#${uid})`" style="transition: d 1.8s linear" />
    <path
      :d="linePath"
      fill="none"
      :stroke="clr"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      style="transition: d 1.8s linear"
    />
    <circle
      v-if="lastPt"
      :cx="lastPt[0]"
      :cy="lastPt[1]"
      r="3"
      :fill="clr"
      style="
        transition:
          cx 1.8s linear,
          cy 1.8s linear;
      "
    />
  </svg>
</template>
