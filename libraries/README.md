# The libraries this repository ships

A library is a `.lib` file. `docs/LANGUAGE.md` section 6 states the language.

## `endpoint.lib`

Technologies and threats for a macOS endpoint: a system extension, the
Endpoint Security client, the keychain, an MDM channel, TCC, Gatekeeper,
launchd, a kernel extension, an XPC service and a unix domain socket.

Copy it into a project to use it:

```
cp libraries/endpoint.lib <project>/threatmodel/library/
```

The file is this repository's own content. It is not vendored, it is not in
`library.lock.json`, and `threatmodeller library verify` says nothing about
it.
