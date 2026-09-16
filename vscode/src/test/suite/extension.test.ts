import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';

import {
    defaultExecutable,
    executablePath,
    makeClient,
    missingExecutableMessage,
    startClient
} from '../../extension';

const extensionId = 'craigjbass.threatmodeller';
const extensionRoot = path.resolve(__dirname, '../../../');
const fixtures = path.join(extensionRoot, 'test-fixtures');
const fakeExecutable = path.join(fixtures, 'fake-threatmodeller.js');
const sampleProject = path.join(fixtures, 'project');

/// Gives the extension, and fails the test when VS Code did not load it.
function extension(): vscode.Extension<unknown> {
    const found = vscode.extensions.getExtension(extensionId);
    assert.ok(found, `VS Code loaded no extension named ${extensionId}`);
    return found;
}

/// Names a log file the fake executable writes to, and empties it.
function newLog(name: string): string {
    const file = path.join(os.tmpdir(), `threatmodeller-${name}-${process.pid}.log`);
    fs.writeFileSync(file, '');
    return file;
}

/// Reads the lines the fake executable wrote.
function logLines(file: string): string[] {
    if (!fs.existsSync(file)) { return []; }
    return fs.readFileSync(file, 'utf8').split('\n').filter((line) => line.length > 0);
}

/// Waits until the test says the wait is over, or the time runs out.
async function waitFor(isDone: () => boolean, message: string): Promise<void> {
    for (let tries = 0; tries < 200; tries += 1) {
        if (isDone()) { return; }
        await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.fail(message);
}

describe('the extension', () => {
    before(async () => {
        await extension().activate();
    });

    describe('the file associations', () => {
        const associations: [string, string][] = [
            ['model.arch', 'threatmodeller-architecture'],
            ['model.controls', 'threatmodeller-controls'],
            ['shared.lib', 'threatmodeller-library'],
            ['theft.attacktree', 'threatmodeller-attacktree'],
            ['answers.governance', 'threatmodeller-governance'],
            ['policy.hcl', 'threatmodeller-policy']
        ];

        for (const [name, languageId] of associations) {
            it(`reads ${name} as ${languageId}`, async () => {
                const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatmodeller-files-'));
                const file = path.join(directory, name);
                fs.writeFileSync(file, '# a file the test opens\n');
                const document = await vscode.workspace.openTextDocument(vscode.Uri.file(file));
                assert.strictEqual(document.languageId, languageId);
            });
        }
    });

    describe('the executable setting', () => {
        it('defaults to the name on PATH', () => {
            const setting = vscode.workspace
                .getConfiguration('threatmodeller')
                .inspect<string>('path');
            assert.strictEqual(setting?.defaultValue, 'threatmodeller');
            assert.strictEqual(defaultExecutable, 'threatmodeller');
        });

        it('reads the path the setting states', async () => {
            const configuration = vscode.workspace.getConfiguration('threatmodeller');
            await configuration.update('path', fakeExecutable, vscode.ConfigurationTarget.Global);
            assert.strictEqual(executablePath(), fakeExecutable);
            await configuration.update('path', undefined, vscode.ConfigurationTarget.Global);
            assert.strictEqual(executablePath(), 'threatmodeller');
        });

        it('reads the name on PATH when the setting is empty', async () => {
            const configuration = vscode.workspace.getConfiguration('threatmodeller');
            await configuration.update('path', '   ', vscode.ConfigurationTarget.Global);
            assert.strictEqual(executablePath(), 'threatmodeller');
            await configuration.update('path', undefined, vscode.ConfigurationTarget.Global);
        });
    });

    describe('the commands', () => {
        it('registers Check, Compile and Draw', async () => {
            const commands = await vscode.commands.getCommands(true);
            assert.ok(commands.includes('threatmodeller.check'), 'threatmodeller.check is not registered');
            assert.ok(commands.includes('threatmodeller.compile'), 'threatmodeller.compile is not registered');
            assert.ok(commands.includes('threatmodeller.draw'), 'threatmodeller.draw is not registered');
        });

        for (const verb of ['check', 'compile', 'draw']) {
            it(`runs ${verb} on the workspace`, async () => {
                const log = newLog(`command-${verb}`);
                process.env.TM_FAKE_LOG = log;
                const configuration = vscode.workspace.getConfiguration('threatmodeller');
                await configuration.update('path', fakeExecutable, vscode.ConfigurationTarget.Global);
                try {
                    await vscode.commands.executeCommand(`threatmodeller.${verb}`);
                    await waitFor(
                        () => logLines(log).some((line) => line.startsWith(`run ${verb} `)),
                        `the fake executable was not asked to run ${verb}`
                    );
                    const line = logLines(log).find((each) => each.startsWith(`run ${verb} `)) ?? '';
                    assert.ok(
                        line.endsWith(sampleProject),
                        `${verb} ran on "${line}", and not on ${sampleProject}`
                    );
                } finally {
                    await configuration.update('path', undefined, vscode.ConfigurationTarget.Global);
                    delete process.env.TM_FAKE_LOG;
                }
            });
        }
    });

    describe('the language client', () => {
        it('asks the server about every language', () => {
            const client = makeClient(fakeExecutable);
            const selector = client.clientOptions.documentSelector as { language: string }[];
            assert.deepStrictEqual(
                selector.map((each) => each.language),
                [
                    'threatmodeller-architecture',
                    'threatmodeller-controls',
                    'threatmodeller-library',
                    'threatmodeller-attacktree',
                    'threatmodeller-governance',
                    'threatmodeller-policy'
                ]
            );
        });

        it('sends initialize to the server the setting names', async () => {
            const log = newLog('initialize');
            const client = makeClient(fakeExecutable, { TM_FAKE_LOG: log });
            await client.start();
            try {
                await waitFor(
                    () => logLines(log).includes('message initialize'),
                    'the client sent no initialize to the fake server'
                );
                assert.ok(logLines(log).includes('start lsp'), 'the client did not start the server with lsp');
                // The server colours the files, so the client reads the
                // legend the server states and needs no grammar of its own.
                const capabilities = client.initializeResult?.capabilities;
                assert.deepStrictEqual(
                    capabilities?.semanticTokensProvider?.legend.tokenTypes,
                    ['keyword', 'string', 'number', 'comment', 'operator', 'variable']
                );
            } finally {
                await client.stop();
            }
        });

        it('shows one message that names the setting when the executable is missing', async () => {
            const missing = path.join(os.tmpdir(), 'threatmodeller-that-is-not-there');
            const shown: string[] = [];
            const started = await startClient(missing, (message) => shown.push(message));
            assert.strictEqual(started, undefined, 'the client started with a missing executable');
            assert.strictEqual(shown.length, 1, `one message is shown, and not ${shown.length}`);
            assert.ok(
                shown[0].includes('threatmodeller.path'),
                `the message does not name the setting: ${shown[0]}`
            );
            assert.ok(shown[0].includes(missing), `the message does not name the path: ${shown[0]}`);
        });
    });

    describe('the missing executable message', () => {
        it('names the setting and the path once', () => {
            const message = missingExecutableMessage('/nowhere/threatmodeller');
            assert.ok(message.includes('threatmodeller.path'));
            assert.ok(message.includes('/nowhere/threatmodeller'));
        });
    });
});
