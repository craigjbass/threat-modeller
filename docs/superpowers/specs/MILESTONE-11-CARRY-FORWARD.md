# Carry-forward after Milestone 11

What Milestone 11 closed, and what still stands.

## Closed in Milestone 11

- **A third language.** `.lib` files, read by the lexer and the block syntax
  `.arch` and `.controls` already use: a `library` block holding `technology`
  and `threat` blocks, with `mitre` blocks and `control` statements. It has the
  same properties the other two hold: every fault names a line and a column,
  parse-write-parse gives the same value tree, and a canonical file is
  reproduced byte for byte.
- **The prefix rule.** A library's label is a provider id, and every id the file
  declares is minted `<label>-<id>`, so two teams can both define
  `cribl-stream`. A `threats` entry the library declares is prefixed; any other
  id stays bare and belongs to the vendored catalogue.
- **`MergedCatalogue`.** The vendored catalogue and the project's libraries read
  as one behind the existing `TechnologyCatalogue` port. The existing catalogue
  contract runs against it with no library, which proves the merge is
  transparent, and again with one.
- **The project convention.** `threatmodel/library/*.lib`, found by
  `ProjectConvention`, so the window and the executable cannot disagree.
- **`LoadLibraries`**, which refuses a `.lib` that does not parse, two libraries
  with one label, and a severity, stride category or service category the
  taxonomy does not hold.
- **Vendoring.** `LibraryFetching` with `GitLibraryFetcher` behind it, and the
  six verbs `library add`, `update`, `remove`, `list`, `verify` and `outdated`,
  with exit code 4 for a fetch that failed. `library.lock.json` pins each
  library by label, with the repository, the tag and the `sha256` of each file.
  `sha256` is written by hand in `LibraryLock`, because `CryptoKit` is an Apple
  framework, and it is checked against the four published test vectors.
- **The Libraries sheet**, over `LibrarySession`, which calls the same use cases
  the verbs call.
- **The sandbox is gone.** A child process inherits its parent's container, so
  `git` inside one cannot read the user's `~/.ssh` or reach their `ssh-agent`.
  The Hardened Runtime, the Developer ID signature and notarization do not
  change. `RecentProjects` stores a path rather than a bookmark, and reads an
  older list that carries one.
- **`ProjectSourceGateway.delete`**, with the contract stating that deleting a
  file that is not there is not a fault.

## Still open

1. **A library cannot define a category, a severity or a stride category.** The
   taxonomy stays the vendored one, so a technology picks from its fourteen
   categories. A team whose domain is missing, such as operational technology,
   has no category to name.
2. **A library cannot define a pathway mitigation**, and cannot mark a threat as
   a pathway threat.
3. **A library cannot override a catalogue entry.** A team that wants a
   different severity for one model uses the per-model severity override.
4. **There is no index, so there is no browsing and no search.** A user adds a
   library by naming its repository and its tag. An index needs a host, a
   format and a rule about who may publish.
5. **`ListOutdatedLibraries` compares tags as text, not as versions**, so `v10`
   sorts before `v9`. It takes the last tag in sorted order.
6. **`outdated` reads every tag a repository holds** and keeps only the last, so
   a repository with thousands of tags does more work than it needs to.
7. **The About window does not list the libraries and their tags.** The
   Libraries sheet says it, and the About window says only the catalogue.
8. **A private repository needs the user's own `git` access.** This application
   holds no credential, reads none and prompts for none, so a repository the
   user's `git` cannot read is one the application cannot read.
9. **`GitLibraryFetcher` has no cancel.** The Libraries sheet disables its
   buttons while a fetch runs, and the fetch is killed after 60 seconds, but a
   person cannot stop one that has started.
10. **`LibrarySession` runs its use cases on the main actor.** A slow `git` sits
    on it for as long as the fetch takes, up to the 60 second timeout.
11. **A `.lib` file is never written by the application.** `LibraryWriter`
    exists and is tested, and no verb and no button calls it. `format` rewrites
    `.arch` files only.
12. **Nothing warns when a vendored library's `catalogue` tag differs from the
    catalogue in use**, though the `.arch` drift banner does the same job for a
    system.
