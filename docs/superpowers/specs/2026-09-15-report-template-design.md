# The report template

**Status:** decided, 15 September 2026.

## The problem

The report's structure is written into `ExportModelAsMarkdown`: the title, then
the document control table, the executive summary, the scope, and so on to the
appendices. A security review board that wants its own cover, its own order,
its own heading names or a classification banner on every page edits the file
after every compile, and the next compile takes the edit away.

## The decision

A template is a **Markdown file with named slots and no logic**.

```markdown
---
banner: OFFICIAL — SENSITIVE
cover: true
cover_title: Payments threat model
cover_subtitle: Prepared for the security review board
---

# {{system_name}}

{{executive_summary}}

## Our own words

The board reads this section before the numbers.

{{findings}}
{{threat_register}}
```

Three rules decide the language:

1. **A slot is `{{name}}` on a line of its own.** The writer replaces the line
   with that section, whole. A slot inside a sentence is not read as a slot.
2. **Everything else is copied out byte for byte.** A team writes its own
   headings, its own paragraphs, its own tables, and the writer does not touch
   them.
3. **There is no logic.** No condition, no loop, no expression. A team that
   wants a section left out omits its slot; a section with nothing to say
   still writes nothing, the way it does today.

### Why no logic

A template language with conditions becomes a program nobody tests. The
report already decides what to write: a section with nothing to say writes no
lines. The template decides only the order, the words around the sections, and
which sections a reader sees.

## The slots

One slot per section the report writes, named after the section:

| Slot | What it writes |
| --- | --- |
| `system_name` | the system's name, as a line of text with no heading |
| `catalogue_tag` | the sentence naming the catalogue this was assessed against |
| `document_control` | the document control table |
| `executive_summary` | the one page a reader reads first |
| `scope` | the use cases and the exclusions |
| `data_inventory` | one row per named asset |
| `third_parties` | one row per party outside the team |
| `policy` | the rules the project states and whether this system keeps them |
| `risk_over_time` | the history graph and its table |
| `what_changed` | what moved since the previous sampled commit |
| `rollups` | the roll-up tables |
| `threat_pictures` | the top residual threats, each with its diagram |
| `methodology` | what the numbers mean |
| `findings` | the threats a reader must act on |
| `leverage` | what a team could do, by what it removes |
| `attack_paths` | the paths the trace found |
| `attack_trees` | the trees a person wrote |
| `protection_dependencies` | what each reduction rests on |
| `recommendations` | what a team wrote against each threat |
| `accepted_risks` | the risks the organisation decided to carry |
| `assumptions` | what the model takes on trust |
| `threat_actors` | the adversaries this assessment is written against |
| `glossary` | the words the report uses |
| `threat_register` | Appendix A: every threat in full |
| `model_inventory` | Appendix B: what the model holds |
| `attack_paths_appendix` | the paths the narrative did not carry |
| `diagrams` | the pictures the team keeps beside the diagram |

A slot the template omits is not written. A slot named twice is a diagnostic:
a section written twice is a report nobody can read. A slot the list does not
hold is a diagnostic naming it and naming the slots that exist.

## The front matter

The file may open with a `---` line, a block of `name: value` lines, and a
closing `---` line. The fields:

| Field | Type | What it does |
| --- | --- | --- |
| `banner` | text | a line at the top of every page of the HTML and the PDF, and the first line of the Markdown |
| `cover` | `true` or `false` | whether the HTML and the PDF open with a cover page |
| `cover_title` | text | the cover's title. The system's name when the field is absent |
| `cover_subtitle` | text | the line under the cover's title |

No other field is read: an unknown field is a diagnostic naming it.

Front matter is not YAML. It is `name: value` per line, the value being the
rest of the line with the spaces at each end taken off. A value holding a
colon is kept whole.

## The default

The executable ships the default template, and it is the shape the report has
today: the same sections, in the same order, with the same title line. A
project that names no template renders through it, and the bytes are the bytes
the writer produced before this existed. One test renders every sample both
ways and states that the two are the same.

## How a project names one

- `threatmodeller report --template <file>` for one run.
- `template = "<file>"` in `threatmodel/policy.hcl` for every run. The path is
  read from the project root.

The flag wins over the file, the way every other flag does.

## What this does not do

- No template for the HTML page's own frame: the page is built from the
  Markdown, so a template changes both.
- No partials, no include, no inheritance. A team that wants one preamble in
  three templates copies it into three files, and a diff shows all three.
- No template for `export`: a program reading JSON reads the schema, not a
  layout.
