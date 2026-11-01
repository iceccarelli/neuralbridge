// Kept free of imports on purpose: tests/test_site_honesty.py runs this file directly under Node
// (type stripping), which must work in a checkout that has not run `npm ci`.

/**
 * The first plain-prose paragraph of a markdown document, as one line of text for a meta
 * description: headings, HTML comments, fenced code, tables, lists, block quotes, include
 * directives and capitals-only arrow diagrams are skipped; links, code and emphasis are reduced to their words; the result is cut
 * at a word boundary at or before 200 characters. Empty string when the document has no prose.
 */
export function firstParagraph(markdown: string): string {
  const body = markdown.replace(/<!--[\s\S]*?-->/g, '').replace(/^(```|~~~)[\s\S]*?^\1/gm, '');
  for (const block of body.split(/\n\s*\n/)) {
    const text = block.trim();
    if (!text || /^(#|\||>|[-*+] |\d+\. |!!!|--8<--|<|---)/.test(text)) continue;
    // An arrow chain in capitals (CHANGE.md opens with one) is a diagram, not prose: `>` has no place in a description.
    if (/->|=>|→/.test(text) && !/[a-z]{3}/.test(text)) continue;
    const plain = text
      // One line first: an emphasised span may run across a line break in the source.
      .replace(/\s+/g, ' ')
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/`/g, '')
      // Emphasis markers come off only where they open or close a span: snake_case and 2*3 keep theirs.
      .replace(/(\*\*|__)(\S(?:.*?\S)?)\1/g, '$2')
      .replace(/(^|[\s(])([*_])(\S(?:.*?\S)?)\2(?=$|[\s).,;:!?])/g, '$1$3')
      .replace(/\s+/g, ' ')
      .trim();
    if (plain.length < 20) continue;
    if (plain.length <= 200) return plain;
    const cut = plain.slice(0, 200);
    return `${cut.slice(0, Math.max(cut.lastIndexOf(' '), 1)).replace(/[,;:]$/, '')}…`;
  }
  return '';
}
