<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue';
import { EditorState, Compartment } from '@codemirror/state';
import {
  EditorView,
  keymap,
  lineNumbers,
  highlightActiveLine,
  highlightActiveLineGutter,
} from '@codemirror/view';
import { yaml } from '@codemirror/lang-yaml';
import {
  foldGutter,
  indentOnInput,
  bracketMatching,
  syntaxHighlighting,
  HighlightStyle,
  indentUnit,
} from '@codemirror/language';
import { history, historyKeymap, defaultKeymap, indentWithTab } from '@codemirror/commands';
import { autocompletion, completionKeymap, startCompletion } from '@codemirror/autocomplete';
import { linter, lintGutter } from '@codemirror/lint';
import { tags } from '@lezer/highlight';
import { yamlIssues, yamlKeys, yamlValues, type YamlProfile } from '@/lib/yaml-assist';
const props = withDefaults(
  defineProps<{
    modelValue: string;
    profile: YamlProfile;
    readonly?: boolean;
    label?: string;
  }>(),
  { readonly: false, label: 'YAML file content' },
);
const emit = defineEmits<{ 'update:modelValue': [string] }>(),
  host = ref<HTMLElement>(),
  readOnly = new Compartment();
let view: EditorView | undefined;
function suggest() {
  if (view) {
    view.focus();
    startCompletion(view);
  }
}
defineExpose({ suggest });
onMounted(() => {
  view = new EditorView({
    parent: host.value,
    state: EditorState.create({
      doc: props.modelValue,
      extensions: [
        lineNumbers(),
        highlightActiveLine(),
        highlightActiveLineGutter(),
        foldGutter(),
        history(),
        bracketMatching(),
        indentOnInput(),
        indentUnit.of('  '),
        yaml(),
        lintGutter(),
        readOnly.of([EditorState.readOnly.of(props.readonly), EditorView.editable.of(!props.readonly)]),
        keymap.of([...defaultKeymap, ...historyKeymap, ...completionKeymap, indentWithTab]),
        syntaxHighlighting(
          HighlightStyle.define([
            {
              tag: [tags.propertyName, tags.labelName],
              color: 'var(--primary)',
            },
            {
              tag: [tags.string, tags.special(tags.string)],
              color: 'light-dark(#166534,#86efac)',
            },
            {
              tag: [tags.bool, tags.number, tags.null],
              color: 'light-dark(#7c3aed,#c4b5fd)',
            },
            { tag: tags.comment, color: 'var(--muted-foreground)' },
            { tag: tags.keyword, color: 'light-dark(#b45309,#fbbf24)' },
          ]),
        ),
        EditorView.theme({
          '&': {
            fontSize: '13px',
            backgroundColor: 'var(--card)',
            color: 'var(--foreground)',
          },
          '.cm-content': {
            fontFamily: 'ui-monospace,monospace',
            minHeight: '380px',
          },
          '.cm-scroller': { overflow: 'auto', maxHeight: '65vh' },
          '.cm-gutters': {
            backgroundColor: 'var(--muted)',
            color: 'var(--muted-foreground)',
            border: 'none',
          },
          '.cm-activeLine': {
            backgroundColor: 'color-mix(in srgb, var(--muted) 35%, transparent)',
          },
          '.cm-tooltip': {
            backgroundColor: 'var(--popover)',
            color: 'var(--popover-foreground)',
            border: '1px solid var(--border)',
          },
          '.cm-cursor': { borderLeftColor: 'var(--foreground)' },
          '&.cm-focused': {
            outline: '2px solid var(--ring)',
            outlineOffset: '-2px',
          },
        }),
        EditorView.contentAttributes.of({
          'aria-label': props.label,
          'aria-multiline': 'true',
          spellcheck: 'false',
          autocomplete: 'off',
        }),
        linter((editor) =>
          yamlIssues(editor.state.doc.toString()).map((issue) => ({
            ...issue,
            from: Math.min(issue.from, editor.state.doc.length),
            to: Math.min(Math.max(issue.from, issue.to), editor.state.doc.length),
          })),
        ),
        autocompletion({
          override: [
            (context) => {
              if (props.readonly) return null;
              const word = context.matchBefore(/[\w./@-]*/);
              if (!word || (!context.explicit && word.from === word.to)) return null;
              const before = context.state.sliceDoc(0, context.pos),
                line = context.state.doc.lineAt(context.pos),
                prefix = context.state.sliceDoc(line.from, context.pos);
              const values = yamlValues(props.profile, prefix);
              if (prefix.includes(':') && !values.length) return null;
              const keys = values.length ? values : yamlKeys(props.profile, before);
              return {
                from: word.from,
                options: keys.map((label) => ({
                  label,
                  type: values.length ? 'enum' : 'property',
                  apply: values.length ? label : label + ': ',
                  detail: values.length ? 'value' : props.profile + ' key',
                })),
                validFor: /^[\w./@-]*$/,
              };
            },
          ],
        }),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) emit('update:modelValue', update.state.doc.toString());
        }),
      ],
    }),
  });
});
watch(
  () => props.modelValue,
  (value) => {
    if (view && value !== view.state.doc.toString())
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: value },
      });
  },
);
watch(
  () => props.readonly,
  (value) =>
    view?.dispatch({
      effects: readOnly.reconfigure([EditorState.readOnly.of(value), EditorView.editable.of(!value)]),
    }),
);
onUnmounted(() => {
  view?.destroy();
  view = undefined;
});
</script>
<template>
  <div ref="host" class="overflow-hidden rounded-lg border" />
</template>
