# The library index

**Status:** approved. Written before the code, because the issue asks for the
host, the format and the publishing rule to be decided first.

**Issue:** #11, "There is no library index, so there is no browsing and no
search".

## 1. What a person cannot do today

A person adds a library by typing its repository and its tag. That works for a
team that already knows its own repositories, and it works for nobody else: a
person who wants a library for a technology they do not model yet has nothing
to look at.

## 2. The host

**The index is a git repository.** It is read with the same `git` the
application already runs for a library, so:

- no server is written, run or paid for,
- no credential is invented: a private index works because the person's own
  `git` reads it,
- a team points at an index of its own by naming a repository, the way it names
  a library.

The default index is `https://github.com/craigjbass/threat-modeller`, and
`ProjectConvention.defaultLibraryIndex` states it. A person changes it in the
Libraries sheet, and the choice is kept in `UserDefaults` under
`libraryIndexRepository`.

WARNING: reading an index runs `git clone --depth 1` of that repository and
reads one file from it. Nothing in an index is executed, and nothing in an
index is trusted with more than a name: adding a library from an entry fetches
that library's own repository, which the person's own `git` reads with the
person's own access.

## 3. The format

One file, `index.json`, at the index repository's root:

```json
{
  "version": 1,
  "libraries": [
    {
      "label": "acme",
      "name": "Acme Platform",
      "description": "Acme's own services, and the threats they carry.",
      "repository": "https://github.com/acme/threat-library",
      "tags": ["v1.2.0", "v1.1.0"],
      "homepage": "https://acme.example/threat-library"
    }
  ]
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `version` | yes | the format version. This document states 1. |
| `label` | yes | the library's label, which is its provider id |
| `name` | yes | what a person reads |
| `description` | no | one line about what the library holds |
| `repository` | yes | what `threatmodeller library add` is given |
| `tags` | no | the tags the entry states, newest first. The newest is offered. |
| `homepage` | no | where a person reads more |

A file whose `version` is not 1 is refused with a message naming the version,
because a later format may mean something else by the same words.

An entry with no `tags` is listed and offers no tag: a person types the tag.
The application never reads the library's repository while browsing, so
browsing costs one clone whatever the index holds.

## 4. Who may publish

**Anyone may run an index.** It is a git repository with one file in it.

The default index is a repository this project owns. An entry is added to it by
a pull request, and the rule for accepting one is:

1. The repository the entry names is readable without a credential, or the
   entry states that it is private.
2. The `.lib` file at that repository's root parses.
3. The entry states a real name and a real description, in the register
   `CLAUDE.md` states.

Nothing else is checked, and nothing is promised: an entry in the index is a
pointer, not an endorsement. The sheet says so.

## 5. What the application does

- The index is read **only when a person asks**. Nothing reads it at launch,
  and nothing reads it when the sheet opens.
- The sheet holds *Browse Index…*. It reads the index, lists what it holds and
  narrows the list by typed text, over the name, the label and the description.
- A row's *Add* fetches that library's repository at the tag the entry states,
  through the same `AddLibrary` use case the typed form calls.
- A machine with no network gets the sheet as it is today, with the message
  the fetch failed with, and adding a library by repository and tag still
  works.

## 6. What this does not do

- No rating, no download count, no popularity order. The index is a list.
- No signing. A library is trusted the way a git repository is trusted, which
  is what the lock file's `sha256` already records.
- No automatic update of the index. A person presses the button.
