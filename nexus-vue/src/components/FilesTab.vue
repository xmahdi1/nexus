<script setup lang="ts">
import { ref, watch } from 'vue';
import { toast } from 'vue-sonner';
import {
  Folder,
  FileText,
  Download,
  Trash2,
  Upload,
  FolderPlus,
  Loader2,
  RotateCcw,
  ChevronRight,
  X,
  AlertTriangle,
  FileCode,
  Pencil,
  Save,
  Ban,
} from '@lucide/vue';
import { api } from '@/lib/api';
import type { FileEntry } from '@/lib/api';
import { useConfirm } from '@/composables/useConfirm';
import Button from '@/components/ui/Button.vue';

const props = defineProps<{ serverId: string }>();
const { confirm } = useConfirm();

const BINARY_EXT = new Set([
  'jar',
  'war',
  'ear',
  'class',
  'deb',
  'rpm',
  'pkg',
  'dmg',
  'exe',
  'msi',
  'apk',
  'ipa',
  'zip',
  'tar',
  'gz',
  'bz2',
  'xz',
  '7z',
  'rar',
  'tgz',
  'zst',
  'png',
  'jpg',
  'jpeg',
  'gif',
  'webp',
  'ico',
  'bmp',
  'tiff',
  'avif',
  'mp4',
  'mp3',
  'wav',
  'avi',
  'mkv',
  'mov',
  'flac',
  'ogg',
  'aac',
  'pdf',
  'docx',
  'xlsx',
  'pptx',
  'doc',
  'xls',
  'ppt',
  'so',
  'dylib',
  'dll',
  'bin',
  'img',
  'iso',
  'o',
  'a',
  'db',
  'sqlite',
  'sqlite3',
]);

const currentPath = ref('/');
const pathInput = ref('/');
const entries = ref<FileEntry[]>([]);
const loading = ref(false);
const loadingRow = ref<string | null>(null);
const error = ref('');
const uploading = ref(false);
const mkdirOpen = ref(false);
const newDirName = ref('');
const fileInput = ref<HTMLInputElement>();

const modal = ref(false);
const previewEntry = ref<FileEntry | null>(null);
const previewContent = ref('');
const originalContent = ref('');
const previewTruncated = ref(false);
const previewBinary = ref(false);
const previewLoading = ref(false);
const editing = ref(false);
const saving = ref(false);

function getExt(name: string) {
  const base = name.split('/').pop() ?? name;
  const dot = base.lastIndexOf('.');
  return dot <= 0 ? base.toLowerCase() : base.slice(dot + 1).toLowerCase();
}

function isText(name: string) {
  return !BINARY_EXT.has(getExt(name));
}

function crumbs() {
  const parts = currentPath.value.split('/').filter(Boolean);
  const result = [{ label: '/', path: '/' }];
  let acc = '';
  for (const p of parts) {
    acc += '/' + p;
    result.push({ label: p, path: acc });
  }
  return result;
}

function fmtSize(b: number) {
  if (b === 0) return '—';
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
  return b + ' B';
}

function fmtDate(d: string) {
  return new Date(d).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

async function navigate(p: string) {
  loading.value = true;
  error.value = '';
  try {
    const res = await api.files.list(props.serverId, p);
    currentPath.value = res.path;
    pathInput.value = res.path;
    entries.value = res.entries;
  } catch {
    const fakeEntry: FileEntry = {
      name: p.split('/').pop() ?? p,
      path: p,
      isDir: false,
      size: 0,
      modTime: '',
      mode: '',
    };
    const opened = await openPreview(fakeEntry);
    if (!opened) error.value = `"${p}" is not a directory and could not be previewed`;
  } finally {
    loading.value = false;
  }
}

function onPathKey(e: KeyboardEvent) {
  if (e.key === 'Enter') navigate(pathInput.value);
}

async function openPreview(entry: FileEntry): Promise<boolean> {
  if (entry.isDir) return false;
  previewEntry.value = entry;
  previewContent.value = '';
  originalContent.value = '';
  previewTruncated.value = false;
  previewBinary.value = false;
  editing.value = false;
  previewLoading.value = true;
  modal.value = true;
  try {
    const res = await api.files.preview(props.serverId, entry.path);
    previewContent.value = res.content;
    originalContent.value = res.content;
    previewTruncated.value = res.truncated;
    previewBinary.value = res.binary;
    return true;
  } catch (e) {
    modal.value = false;
    toast.error(e instanceof Error ? e.message : 'Failed to load preview');
    return false;
  } finally {
    previewLoading.value = false;
  }
}

async function handleClick(entry: FileEntry) {
  if (entry.isDir) {
    navigate(entry.path);
    return;
  }
  loadingRow.value = entry.path;
  await openPreview(entry);
  loadingRow.value = null;
}

function startEdit() {
  editing.value = true;
}

function cancelEdit() {
  previewContent.value = originalContent.value;
  editing.value = false;
}

async function saveEdit() {
  if (!previewEntry.value) return;
  saving.value = true;
  try {
    await api.files.write(props.serverId, previewEntry.value.path, previewContent.value);
    originalContent.value = previewContent.value;
    editing.value = false;
    toast.success('File saved');
    const idx = entries.value.findIndex((e) => e.path === previewEntry.value!.path);
    if (idx >= 0) entries.value[idx].size = new TextEncoder().encode(previewContent.value).length;
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to save file');
  } finally {
    saving.value = false;
  }
}

async function closeModal() {
  if (editing.value && previewContent.value !== originalContent.value) {
    const ok = await confirm({
      title: 'Discard changes?',
      message: 'You have unsaved edits to this file. Closing now will discard them.',
      confirmText: 'Discard',
      destructive: true,
    });
    if (!ok) return;
  }
  modal.value = false;
  previewEntry.value = null;
  editing.value = false;
}

async function download(entry: FileEntry) {
  try {
    const blob = await api.files.download(props.serverId, entry.path);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = entry.name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Download failed');
  }
}

async function onFileSelected(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0];
  if (!file) return;
  uploading.value = true;
  try {
    await api.files.upload(props.serverId, currentPath.value, file);
    toast.success(`Uploaded ${file.name}`);
    await navigate(currentPath.value);
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Upload failed');
  } finally {
    uploading.value = false;
    if (fileInput.value) fileInput.value.value = '';
  }
}

async function deleteEntry(entry: FileEntry) {
  const ok = await confirm({
    title: entry.isDir ? 'Remove directory' : 'Delete file',
    message: `Delete ${entry.path} on ${props.serverId}? ${entry.isDir ? 'This recursively removes directory contents; an interrupted deletion may be partial.' : 'This cannot be undone.'}`,
    confirmText: 'Delete',
    destructive: true,
  });
  if (!ok) return;
  try {
    await api.files.delete(props.serverId, entry.path);
    toast.success(`Deleted ${entry.name}`);
    if (previewEntry.value?.path === entry.path) {
      modal.value = false;
      previewEntry.value = null;
    }
    entries.value = entries.value.filter((e) => e.path !== entry.path);
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Delete failed');
  }
}

async function createDir() {
  const name = newDirName.value.trim();
  if (!name) return;
  const fullPath = currentPath.value.replace(/\/$/, '') + '/' + name;
  try {
    await api.files.mkdir(props.serverId, fullPath);
    toast.success(`Created ${name}`);
    mkdirOpen.value = false;
    newDirName.value = '';
    await navigate(currentPath.value);
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to create directory');
  }
}

watch(
  () => props.serverId,
  () => navigate('/'),
  { immediate: true },
);
</script>

<template>
  <div class="space-y-3">
    <div class="flex gap-2 flex-wrap sm:flex-nowrap">
      <div class="relative flex-1 min-w-0">
        <Folder class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <input
          v-model="pathInput"
          class="w-full h-9 pl-9 pr-3 rounded-md border bg-background text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50"
          placeholder="/path"
          @keydown="onPathKey"
        />
      </div>
      <Button variant="outline" class="gap-1.5 shrink-0" :disabled="loading" @click="navigate(pathInput)">
        <Loader2 v-if="loading" class="h-3.5 w-3.5 animate-spin" />
        <RotateCcw v-else class="h-3.5 w-3.5" />
        <span class="hidden sm:inline">Go</span>
      </Button>
      <Button variant="outline" class="gap-1.5 shrink-0" @click="mkdirOpen = !mkdirOpen">
        <FolderPlus class="h-3.5 w-3.5" />
        <span class="hidden sm:inline">New folder</span>
      </Button>
      <Button class="gap-1.5 shrink-0" :disabled="uploading" @click="fileInput?.click()">
        <Loader2 v-if="uploading" class="h-3.5 w-3.5 animate-spin" />
        <Upload v-else class="h-3.5 w-3.5" />
        <span class="hidden sm:inline">Upload</span>
      </Button>
      <input ref="fileInput" type="file" class="hidden" @change="onFileSelected" />
    </div>

    <div class="flex items-center gap-0.5 text-sm overflow-x-auto">
      <template v-for="(c, i) in crumbs()" :key="c.path">
        <button
          :class="[
            'px-1 py-0.5 rounded hover:bg-muted transition-colors shrink-0 font-mono text-xs',
            i === crumbs().length - 1 ? 'text-foreground font-medium' : 'text-muted-foreground',
          ]"
          @click="navigate(c.path)"
        >
          {{ c.label }}
        </button>
        <ChevronRight v-if="i < crumbs().length - 1" class="h-3 w-3 text-muted-foreground/40 shrink-0" />
      </template>
    </div>

    <div v-if="mkdirOpen" class="flex gap-2">
      <input
        v-model="newDirName"
        class="flex-1 h-8 px-3 rounded-md border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
        placeholder="New folder name"
        autofocus
        @keydown.enter="createDir"
        @keydown.esc="
          mkdirOpen = false;
          newDirName = '';
        "
      />
      <Button size="sm" class="h-8" @click="createDir">Create</Button>
      <Button
        size="sm"
        variant="outline"
        class="h-8"
        @click="
          mkdirOpen = false;
          newDirName = '';
        "
        >Cancel</Button
      >
    </div>

    <div v-if="error" class="text-sm text-destructive bg-destructive/10 rounded-lg px-4 py-3">
      {{ error }}
    </div>

    <div v-if="loading" class="grid gap-1">
      <div v-for="i in 8" :key="i" class="h-10 rounded-lg bg-muted animate-pulse" />
    </div>

    <div
      v-else-if="!entries.length && !error && !loading"
      class="text-center py-12 text-muted-foreground text-sm border rounded-xl"
    >
      This directory is empty
    </div>

    <div v-else-if="entries.length" class="border rounded-xl overflow-x-auto">
      <table class="w-full text-sm min-w-[300px]">
        <thead class="sticky top-0 z-10 bg-card">
          <tr class="border-b bg-muted/40">
            <th class="text-left px-4 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wide">
              Name
            </th>
            <th
              class="text-left px-4 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wide hidden sm:table-cell"
            >
              Size
            </th>
            <th
              class="text-left px-4 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wide hidden md:table-cell"
            >
              Modified
            </th>
            <th class="px-4 py-2 w-20" />
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="entry in entries"
            :key="entry.path"
            class="border-b last:border-0 hover:bg-muted/20 transition-colors group"
            :class="entry.isDir || isText(entry.name) ? 'cursor-pointer' : 'cursor-default'"
            @click="handleClick(entry)"
          >
            <td class="px-4 py-2.5">
              <div class="flex items-center gap-2">
                <Loader2
                  v-if="loadingRow === entry.path"
                  class="h-4 w-4 text-muted-foreground animate-spin shrink-0"
                />
                <Folder v-else-if="entry.isDir" class="h-4 w-4 text-blue-500 shrink-0" />
                <FileCode v-else-if="isText(entry.name)" class="h-4 w-4 text-emerald-500 shrink-0" />
                <FileText v-else class="h-4 w-4 text-muted-foreground/40 shrink-0" />
                <span :class="['truncate max-w-[140px] sm:max-w-xs', entry.isDir ? 'font-medium' : '']">{{
                  entry.name
                }}</span>
                <span
                  v-if="!entry.isDir && !isText(entry.name)"
                  class="text-[10px] px-1.5 py-px rounded bg-muted text-muted-foreground border shrink-0 font-mono leading-none hidden sm:inline"
                >
                  binary
                </span>
              </div>
            </td>
            <td class="px-4 py-2.5 text-xs text-muted-foreground hidden sm:table-cell">
              {{ entry.isDir ? '—' : fmtSize(entry.size) }}
            </td>
            <td class="px-4 py-2.5 text-xs text-muted-foreground hidden md:table-cell">
              {{ fmtDate(entry.modTime) }}
            </td>
            <td class="px-4 py-2.5" @click.stop>
              <div
                class="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
              >
                <Button
                  v-if="!entry.isDir"
                  size="icon"
                  variant="ghost"
                  class="h-7 w-7"
                  @click="download(entry)"
                >
                  <Download class="h-3.5 w-3.5" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  class="h-7 w-7 text-destructive hover:text-destructive"
                  @click="deleteEntry(entry)"
                >
                  <Trash2 class="h-3.5 w-3.5" />
                </Button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <Transition
    enter-active-class="transition-opacity duration-150"
    enter-from-class="opacity-0"
    leave-active-class="transition-opacity duration-100"
    leave-to-class="opacity-0"
  >
    <div v-if="modal" class="fixed inset-0 z-[200] flex items-end sm:items-center justify-center sm:p-4">
      <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="closeModal" />
      <Transition
        enter-active-class="transition-all duration-150"
        enter-from-class="opacity-0 scale-95"
        enter-to-class="opacity-100 scale-100"
      >
        <div
          v-if="modal"
          class="relative z-10 w-full sm:max-w-4xl bg-card border sm:rounded-2xl rounded-t-2xl shadow-2xl flex flex-col max-h-[90vh]"
        >
          <div class="flex items-center justify-between px-4 sm:px-5 py-3 border-b shrink-0">
            <div class="flex items-center gap-2 min-w-0">
              <FileCode class="h-4 w-4 text-muted-foreground shrink-0" />
              <span class="text-sm font-mono truncate">{{ previewEntry?.path }}</span>
              <span
                v-if="previewTruncated"
                class="text-xs text-yellow-600 bg-yellow-500/10 border border-yellow-500/20 px-1.5 py-0.5 rounded shrink-0 hidden sm:inline"
              >
                truncated at 256 KB
              </span>
              <span
                v-if="editing"
                class="text-xs text-blue-600 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded shrink-0"
              >
                editing
              </span>
            </div>
            <div class="flex items-center gap-2 shrink-0 ml-4">
              <template v-if="!previewBinary && !previewTruncated && !editing">
                <Button size="sm" variant="outline" class="gap-1.5 h-7 text-xs" @click="startEdit">
                  <Pencil class="h-3 w-3" /><span class="hidden sm:inline">Edit</span>
                </Button>
              </template>
              <template v-if="editing">
                <Button
                  size="sm"
                  variant="outline"
                  class="gap-1.5 h-7 text-xs"
                  :disabled="saving"
                  @click="cancelEdit"
                >
                  <Ban class="h-3 w-3" /><span class="hidden sm:inline">Cancel</span>
                </Button>
                <Button
                  size="sm"
                  class="gap-1.5 h-7 text-xs"
                  :disabled="saving || previewContent === originalContent"
                  @click="saveEdit"
                >
                  <Loader2 v-if="saving" class="h-3 w-3 animate-spin" />
                  <Save v-else class="h-3 w-3" />
                  <span class="hidden sm:inline">Save</span>
                </Button>
              </template>
              <Button
                v-if="previewEntry && !editing"
                size="sm"
                variant="outline"
                class="gap-1.5 h-7 text-xs"
                @click="download(previewEntry)"
              >
                <Download class="h-3 w-3" /><span class="hidden sm:inline">Download</span>
              </Button>
              <button class="text-muted-foreground hover:text-foreground" @click="closeModal">
                <X class="h-5 w-5" />
              </button>
            </div>
          </div>
          <div class="overflow-auto flex-1">
            <div
              v-if="previewLoading"
              class="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"
            >
              <Loader2 class="h-4 w-4 animate-spin" />Loading preview…
            </div>
            <div
              v-else-if="previewBinary"
              class="flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground"
            >
              <AlertTriangle class="h-8 w-8" />
              <p class="text-sm">Binary file — cannot be previewed or edited as text</p>
              <Button
                v-if="previewEntry"
                variant="outline"
                class="gap-2 mt-1"
                @click="download(previewEntry)"
              >
                <Download class="h-4 w-4" />Download instead
              </Button>
            </div>
            <template v-else-if="editing">
              <textarea
                v-model="previewContent"
                class="w-full h-[60vh] px-4 sm:px-5 py-4 text-xs font-mono text-foreground bg-card resize-none focus:outline-none leading-relaxed"
                spellcheck="false"
              />
            </template>
            <pre
              v-else-if="previewContent"
              class="px-4 sm:px-5 py-4 text-xs font-mono text-foreground whitespace-pre leading-relaxed overflow-x-auto"
              >{{ previewContent }}</pre>
            <div v-else-if="!previewTruncated" class="py-16 text-center text-sm text-muted-foreground">
              Empty file
            </div>
            <div v-else class="py-16 text-center text-sm text-muted-foreground">
              File too large to edit in-browser (over 256 KB)
              <br />
              <Button
                v-if="previewEntry"
                variant="outline"
                class="gap-2 mt-3"
                @click="download(previewEntry)"
              >
                <Download class="h-4 w-4" />Download to edit locally
              </Button>
            </div>
          </div>
        </div>
      </Transition>
    </div>
  </Transition>
</template>
