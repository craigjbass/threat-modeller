#!/usr/bin/env node
// Stands in for the `threatmodeller` executable in the extension tests.
//
// The script writes one line to the file TM_FAKE_LOG names for each thing it
// is asked to do, so a test reads what the extension asked for.
//
// `fake-threatmodeller.js lsp` speaks the Language Server Protocol on
// standard input and output, and answers `initialize` and `shutdown`.
// Any other verb writes one line on standard output and exits 0.
'use strict';

const fs = require('fs');

const logPath = process.env.TM_FAKE_LOG;

/// Writes one line to the log file, when a test named one.
function log(line) {
    if (!logPath) { return; }
    fs.appendFileSync(logPath, line + '\n');
}

const words = process.argv.slice(2);
const verb = words[0] || '';

if (verb !== 'lsp') {
    log('run ' + words.join(' '));
    process.stdout.write('fake threatmodeller ran ' + words.join(' ') + '\n');
    process.exit(0);
}

log('start lsp');

/// Writes one message back to the client, framed the way the protocol states.
function send(message) {
    const body = JSON.stringify(message);
    const length = Buffer.byteLength(body, 'utf8');
    process.stdout.write('Content-Length: ' + length + '\r\n\r\n' + body);
}

let buffer = Buffer.alloc(0);

process.stdin.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
        const end = buffer.indexOf('\r\n\r\n');
        if (end < 0) { return; }
        const header = buffer.subarray(0, end).toString('ascii');
        const match = /Content-Length: *(\d+)/i.exec(header);
        if (!match) { return; }
        const length = Number(match[1]);
        const start = end + 4;
        if (buffer.length < start + length) { return; }
        const body = buffer.subarray(start, start + length).toString('utf8');
        buffer = buffer.subarray(start + length);
        answer(body);
    }
});

/// Answers one message from the client.
function answer(body) {
    let message;
    try {
        message = JSON.parse(body);
    } catch (error) {
        return;
    }
    const method = message.method;
    if (typeof method === 'string') {
        log('message ' + method);
    }
    if (method === 'initialize') {
        send({
            jsonrpc: '2.0',
            id: message.id,
            result: {
                capabilities: {
                    textDocumentSync: 1,
                    semanticTokensProvider: {
                        legend: {
                            tokenTypes: ['keyword', 'string', 'number', 'comment', 'operator', 'variable'],
                            tokenModifiers: []
                        },
                        full: true
                    }
                },
                serverInfo: { name: 'fake-threatmodeller', version: '1.0.0' }
            }
        });
        return;
    }
    if (method === 'shutdown') {
        send({ jsonrpc: '2.0', id: message.id, result: null });
        return;
    }
    if (method === 'exit') {
        process.exit(0);
    }
}
