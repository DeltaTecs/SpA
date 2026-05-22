/**
 * Minimal, dependency-free Markdown renderer.
 *
 * Report bodies come from LLM output, so every piece of text is HTML-escaped
 * before any markup is added. Raw HTML in the source is never passed through,
 * which keeps the rendered report safe from script injection.
 *
 * `renderMarkdown` is the only public entry point; the remaining functions are
 * block- and inline-level parsing helpers used internally.
 */

const MD_LIST_ITEM_RE = /^(\s*)([-*+]|\d{1,9}[.)])(\s+)(.*)$/;

function escapeHtml(value) {
  return String(value).replace(/[&<>"]/g, (char) => (
    {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[char]
  ));
}

// Renders a Markdown string to a safe HTML string.
export function renderMarkdown(source) {
  if (source === null || source === undefined) {
    return "";
  }
  const lines = String(source).replace(/\r\n?/g, "\n").split("\n");
  const blocks = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block (``` or ~~~).
    const fence = line.match(/^\s*(`{3,}|~{3,})(.*)$/);
    if (fence) {
      const marker = fence[1][0];
      const lang = fence[2].trim().split(/\s+/)[0];
      const body = [];
      i++;
      while (i < lines.length && !new RegExp(`^\\s*${marker}{3,}\\s*$`).test(lines[i])) {
        body.push(lines[i]);
        i++;
      }
      i++; // skip the closing fence (if present)
      const langClass = lang ? ` class="language-${escapeHtml(lang)}"` : "";
      blocks.push(`<pre class="md-code"><code${langClass}>${escapeHtml(body.join("\n"))}</code></pre>`);
      continue;
    }

    // Blank line.
    if (/^\s*$/.test(line)) {
      i++;
      continue;
    }

    // ATX heading (# .. ######).
    const heading = line.match(/^(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (heading) {
      const level = heading[1].length;
      blocks.push(`<h${level} class="md-h${level}">${renderInline(heading[2])}</h${level}>`);
      i++;
      continue;
    }

    // Thematic break.
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) {
      blocks.push('<hr class="md-hr">');
      i++;
      continue;
    }

    // GFM pipe table: a header row followed by a delimiter row.
    if (line.includes("|") && i + 1 < lines.length && isTableDelimiter(lines[i + 1])) {
      const header = line;
      const delimiter = lines[i + 1];
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && !/^\s*$/.test(lines[i])) {
        rows.push(lines[i]);
        i++;
      }
      blocks.push(renderTable(header, delimiter, rows));
      continue;
    }

    // Blockquote.
    if (/^\s*>/.test(line)) {
      const quoted = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) {
        quoted.push(lines[i].replace(/^\s*>\s?/, ""));
        i++;
      }
      blocks.push(`<blockquote class="md-quote">${renderMarkdown(quoted.join("\n"))}</blockquote>`);
      continue;
    }

    // List (ordered or unordered, with indentation-based nesting).
    if (MD_LIST_ITEM_RE.test(line)) {
      const parsed = parseList(lines, i);
      blocks.push(parsed.html);
      i = parsed.next;
      continue;
    }

    // Paragraph: collect lines until a blank line or a new block starts.
    const paragraph = [];
    while (
      i < lines.length &&
      !/^\s*$/.test(lines[i]) &&
      !isBlockStart(lines[i], lines[i + 1])
    ) {
      paragraph.push(lines[i]);
      i++;
    }
    blocks.push(`<p class="md-p">${renderInline(paragraph.join("\n"))}</p>`);
  }

  return blocks.join("\n");
}

// Detects the start of a block-level construct, used to terminate paragraphs.
function isBlockStart(line, nextLine) {
  return (
    /^\s*(`{3,}|~{3,})/.test(line) ||
    /^#{1,6}\s+/.test(line) ||
    /^\s*([-*_])(\s*\1){2,}\s*$/.test(line) ||
    /^\s*>/.test(line) ||
    MD_LIST_ITEM_RE.test(line) ||
    (line.includes("|") && nextLine !== undefined && isTableDelimiter(nextLine))
  );
}

// Parses a list starting at `start`; returns the HTML and the next line index.
function parseList(lines, start) {
  const first = lines[start].match(MD_LIST_ITEM_RE);
  const indent = first[1].length;
  const ordered = /\d/.test(first[2]);
  const tag = ordered ? "ol" : "ul";
  const items = [];
  let i = start;

  const isSibling = (m) => Boolean(m) && m[1].length === indent && /\d/.test(m[2]) === ordered;

  while (i < lines.length) {
    const match = lines[i].match(MD_LIST_ITEM_RE);
    if (!isSibling(match)) {
      // A blank line is allowed between sibling items (loose list).
      if (/^\s*$/.test(lines[i])) {
        let j = i + 1;
        while (j < lines.length && /^\s*$/.test(lines[j])) {
          j++;
        }
        const next = j < lines.length ? lines[j].match(MD_LIST_ITEM_RE) : null;
        if (isSibling(next)) {
          i = j;
          continue;
        }
      }
      break;
    }

    // Lines indented past the marker belong to this item (continuation/nesting).
    const contentIndent = match[1].length + match[2].length + match[3].length;
    const body = [match[4]];
    i++;
    while (i < lines.length) {
      if (/^\s*$/.test(lines[i])) {
        let j = i + 1;
        while (j < lines.length && /^\s*$/.test(lines[j])) {
          j++;
        }
        const sibling = j < lines.length ? lines[j].match(MD_LIST_ITEM_RE) : null;
        const deeper = j < lines.length && lines[j].match(/^(\s*)/)[1].length >= contentIndent;
        if (deeper && !(sibling && sibling[1].length === indent)) {
          body.push("");
          i++;
          continue;
        }
        break;
      }
      const sibling = lines[i].match(MD_LIST_ITEM_RE);
      if (sibling && sibling[1].length === indent) {
        break;
      }
      if (lines[i].match(/^(\s*)/)[1].length < contentIndent) {
        break;
      }
      body.push(lines[i].slice(contentIndent));
      i++;
    }
    items.push(unwrapParagraph(renderMarkdown(body.join("\n"))));
  }

  const rendered = items.map((item) => `<li class="md-li">${item}</li>`).join("");
  return {html: `<${tag} class="md-list">${rendered}</${tag}>`, next: i};
}

// Strips the wrapping <p> from a single-paragraph list item so it renders tight.
function unwrapParagraph(html) {
  const match = html.match(/^<p class="md-p">([\s\S]*)<\/p>$/);
  if (match && !match[1].includes("<p ") && !match[1].includes("</p>")) {
    return match[1];
  }
  return html;
}

function isTableDelimiter(line) {
  return /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/.test(line);
}

// Splits a table row on unescaped pipes, trimming surrounding pipes and spaces.
function splitTableRow(line) {
  let text = line.trim();
  if (text.startsWith("|")) {
    text = text.slice(1);
  }
  if (text.endsWith("|") && !text.endsWith("\\|")) {
    text = text.slice(0, -1);
  }
  const cells = [];
  let current = "";
  for (let k = 0; k < text.length; k++) {
    if (text[k] === "\\" && text[k + 1] === "|") {
      current += "|";
      k++;
    } else if (text[k] === "|") {
      cells.push(current);
      current = "";
    } else {
      current += text[k];
    }
  }
  cells.push(current);
  return cells.map((cell) => cell.trim());
}

function renderTable(headerLine, delimiterLine, bodyLines) {
  const headers = splitTableRow(headerLine);
  const aligns = splitTableRow(delimiterLine).map((cell) => {
    const left = cell.startsWith(":");
    const right = cell.endsWith(":");
    if (left && right) {
      return "center";
    }
    return right ? "right" : left ? "left" : "";
  });
  const alignAttr = (index) => (aligns[index] ? ` style="text-align:${aligns[index]}"` : "");
  const headRow = headers
    .map((cell, index) => `<th${alignAttr(index)}>${renderInline(cell)}</th>`)
    .join("");
  const bodyRows = bodyLines
    .map((line) => {
      const cells = splitTableRow(line);
      const row = headers
        .map((_, index) => `<td${alignAttr(index)}>${renderInline(cells[index] || "")}</td>`)
        .join("");
      return `<tr>${row}</tr>`;
    })
    .join("");
  return `<table class="md-table"><thead><tr>${headRow}</tr></thead><tbody>${bodyRows}</tbody></table>`;
}

// Renders inline Markdown (code spans, links, emphasis) within a block of text.
function renderInline(text) {
  let escaped = escapeHtml(text);
  const codeSpans = [];
  const links = [];

  // Protect code spans first so their contents are never treated as markup.
  escaped = escaped.replace(/(`+)([^`]+?)\1/g, (match, ticks, code) => {
    codeSpans.push(`<code class="md-code-inline">${code.trim()}</code>`);
    return ` C${codeSpans.length - 1} `;
  });

  // Protect links so URLs are not mangled by the emphasis rules.
  escaped = escaped.replace(/\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, (match, label, url) => {
    const href = sanitizeUrl(url);
    const inner = applyEmphasis(label);
    if (!href) {
      return inner;
    }
    links.push(`<a class="md-link" href="${href}" target="_blank" rel="noopener noreferrer">${inner}</a>`);
    return ` L${links.length - 1} `;
  });

  escaped = applyEmphasis(escaped).replace(/\n/g, "<br>");
  escaped = escaped.replace(/ L(\d+) /g, (match, index) => links[Number(index)]);
  escaped = escaped.replace(/ C(\d+) /g, (match, index) => codeSpans[Number(index)]);
  return escaped;
}

function applyEmphasis(text) {
  return text
    .replace(/\*\*\*([\s\S]+?)\*\*\*/g, "<strong><em>$1</em></strong>")
    .replace(/\*\*([\s\S]+?)\*\*/g, "<strong>$1</strong>")
    .replace(/__([\s\S]+?)__/g, "<strong>$1</strong>")
    .replace(/~~([\s\S]+?)~~/g, "<del>$1</del>")
    .replace(/(^|[^\w*])\*(?!\s)([^*]+?)\*(?!\w)/g, "$1<em>$2</em>")
    .replace(/(^|[^\w_])_(?!\s)([^_]+?)_(?!\w)/g, "$1<em>$2</em>");
}

// Allows only safe URL schemes; rejected URLs fall back to plain label text.
function sanitizeUrl(url) {
  const trimmed = url.trim();
  const decoded = trimmed.replace(/&amp;/g, "&");
  if (/^(https?:|mailto:)/i.test(decoded) || /^[/#.]/.test(decoded)) {
    return trimmed;
  }
  return null;
}
