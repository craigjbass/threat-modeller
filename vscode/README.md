# Craig's Threat Modeller for VS Code

Reads the threat modelling source languages in VS Code, through the
language server the `threatmodeller` executable holds.

## What the extension gives

- `.arch`, `.controls`, `.lib`, `.attacktree`, `.governance` and `policy.hcl`
  each read as their own language, with a comment and bracket configuration.
- `threatmodeller lsp` runs as the language server over standard input and
  output. The server publishes the parser's diagnostics, and answers
  completion, hover, go to definition, formatting and semantic tokens, so the
  files colour without a grammar.
- Three commands in the command palette: **Threat Modeller: Check**,
  **Threat Modeller: Compile** and **Threat Modeller: Draw**. Each command
  runs the executable over the first folder of the workspace and writes what
  the executable wrote into the *Craig's Threat Modeller* output channel.

## What the extension needs

The `threatmodeller` command line executable. Install it from a release, or
from the application's *Install Command Line Tool* menu item.

## The setting

| Setting | Default | What it states |
| --- | --- | --- |
| `threatmodeller.path` | `threatmodeller` | The path of the executable. The default reads the name from `PATH`. |

WARNING: the languages stop colouring when the executable is not there. The
extension then shows one message that names `threatmodeller.path`.

## Building the extension

```
cd vscode
npm ci
npm run compile
npm test
```

`scripts/vscode-extension-smoke.sh` runs those three commands.
