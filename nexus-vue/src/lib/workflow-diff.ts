// A review hunk with shared prefix/suffix elided. It is not a patch applier.
export function workflowDiff(original: string, edited: string): string {
  if (original === edited) return '';
  const lines = (text: string) => {
    const result = text.split('\n');
    if (text.endsWith('\n')) result.pop();
    return result;
  };
  const before = lines(original),
    after = lines(edited);
  let prefix = 0,
    suffix = 0;
  while (prefix < before.length && prefix < after.length && before[prefix] === after[prefix]) prefix++;
  while (
    suffix < before.length - prefix &&
    suffix < after.length - prefix &&
    before[before.length - 1 - suffix] === after[after.length - 1 - suffix]
  )
    suffix++;
  if (prefix === before.length && prefix === after.length) return 'Only the final newline differs.';
  const start = Math.max(0, prefix - 3),
    context = Math.min(3, suffix);
  const oldEnd = before.length - suffix,
    newEnd = after.length - suffix;
  return [
    '--- Original',
    '+++ Edited',
    `@@ -${start + 1},${oldEnd - start + context} +${start + 1},${newEnd - start + context} @@`,
    ...before.slice(start, prefix).map((line) => ' ' + line),
    ...before.slice(prefix, oldEnd).map((line) => '-' + line),
    ...after.slice(prefix, newEnd).map((line) => '+' + line),
    ...after.slice(newEnd, newEnd + context).map((line) => ' ' + line),
    ...(!original.endsWith('\n') ? ['Original has no final newline.'] : []),
    ...(!edited.endsWith('\n') ? ['Edited file has no final newline.'] : []),
  ].join('\n');
}
