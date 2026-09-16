import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import {
    CloseAction,
    ErrorAction,
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

/// The name the extension runs when the setting states no path. The name
/// reads from PATH.
export const defaultExecutable = 'threatmodeller';

/// The setting that names the executable, as a user reads it in the settings
/// editor.
export const executableSetting = 'threatmodeller.path';

/// The language ids this extension contributes, in the order the manifest
/// states them.
export const languageIds = [
    'threatmodeller-architecture',
    'threatmodeller-controls',
    'threatmodeller-library',
    'threatmodeller-attacktree',
    'threatmodeller-governance',
    'threatmodeller-policy'
];

/// The verbs the three commands run.
export const commandVerbs = ['check', 'compile', 'draw'];

let client: LanguageClient | undefined;
let channel: vscode.OutputChannel | undefined;
let statedExecutable = '';

/// The path of the executable: the path the setting states, or the name on
/// PATH when the setting is empty.
export function executablePath(): string {
    const stated = vscode.workspace
        .getConfiguration('threatmodeller')
        .get<string>('path');
    const trimmed = (stated ?? '').trim();
    return trimmed.length > 0 ? trimmed : defaultExecutable;
}

/// What a user reads when the extension cannot run the executable.
export function missingExecutableMessage(executable: string): string {
    return (
        `Craig's Threat Modeller cannot run "${executable}". ` +
        `Install the command line executable, or set ${executableSetting} to its path.`
    );
}

/// Says whether a path names a file this machine can run.
///
/// A path that holds a separator names a file, so the check reads that file.
/// A bare name reads from PATH, and the spawn reports a name that is not
/// there.
function isThere(executable: string): boolean {
    if (executable.includes(path.sep) === false && executable.includes('/') === false) {
        return true;
    }
    try {
        fs.accessSync(executable, fs.constants.X_OK);
        return true;
    } catch (error) {
        return false;
    }
}

/// Makes a client that starts `<executable> lsp` and speaks to it over
/// standard input and output.
export function makeClient(
    executable: string,
    environment: Record<string, string> = {}
): LanguageClient {
    const run = {
        command: executable,
        args: ['lsp'],
        transport: TransportKind.stdio,
        options: { env: { ...process.env, ...environment } }
    };
    const serverOptions: ServerOptions = { run, debug: run };
    const clientOptions: LanguageClientOptions = {
        documentSelector: languageIds.map((language) => ({ scheme: 'file', language })),
        // The server reads the files itself, so a failure stays a failure and
        // the client does not start the executable again and again.
        errorHandler: {
            error: () => ({ action: ErrorAction.Shutdown }),
            closed: () => ({ action: CloseAction.DoNotRestart })
        }
    };
    return new LanguageClient(
        'threatmodeller',
        "Craig's Threat Modeller",
        serverOptions,
        clientOptions
    );
}

/// Starts the language client, and gives it back when it started.
///
/// WARNING: an executable that is not there stops the languages from
/// colouring. `report` states one message that names the setting, and the
/// function gives back undefined.
export async function startClient(
    executable: string,
    report: (message: string) => void
): Promise<LanguageClient | undefined> {
    if (isThere(executable) === false) {
        report(missingExecutableMessage(executable));
        return undefined;
    }
    const started = makeClient(executable);
    try {
        await started.start();
        return started;
    } catch (error) {
        report(missingExecutableMessage(executable));
        try {
            await started.stop();
        } catch (stopError) {
            // The server never ran, so there is nothing to stop.
        }
        return undefined;
    }
}

/// The directory the commands run over: the first folder of the workspace.
function workspaceRoot(): string | undefined {
    return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

/// Runs one verb of the executable over one directory, and writes what the
/// executable wrote into the output channel.
export function runVerb(
    executable: string,
    verb: string,
    root: string,
    output: vscode.OutputChannel
): Promise<number> {
    return new Promise((resolve) => {
        output.show(true);
        output.appendLine(`$ ${executable} ${verb} ${root}`);
        const child = spawn(executable, [verb, root], { cwd: root });
        child.stdout.on('data', (data: Buffer) => output.append(data.toString()));
        child.stderr.on('data', (data: Buffer) => output.append(data.toString()));
        child.on('error', () => {
            const message = missingExecutableMessage(executable);
            output.appendLine(message);
            vscode.window.showErrorMessage(message);
            resolve(-1);
        });
        child.on('close', (code) => {
            output.appendLine(`${verb} exited with code ${code ?? 0}`);
            resolve(code ?? 0);
        });
    });
}

/// Starts the extension: the output channel, the three commands, and the
/// language client.
export async function activate(context: vscode.ExtensionContext): Promise<void> {
    channel = vscode.window.createOutputChannel("Craig's Threat Modeller");
    context.subscriptions.push(channel);

    for (const verb of commandVerbs) {
        context.subscriptions.push(
            vscode.commands.registerCommand(`threatmodeller.${verb}`, async () => {
                const root = workspaceRoot();
                if (root === undefined) {
                    vscode.window.showErrorMessage(
                        `Craig's Threat Modeller runs ${verb} over a folder, and this window holds none.`
                    );
                    return;
                }
                await runVerb(executablePath(), verb, root, channel as vscode.OutputChannel);
            })
        );
    }

    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(async (change) => {
            if (change.affectsConfiguration(executableSetting) === false) { return; }
            if (executablePath() === statedExecutable) { return; }
            await restartClient();
        })
    );

    await restartClient();
}

/// Stops the client that runs, and starts one for the executable the setting
/// names now.
async function restartClient(): Promise<void> {
    if (client !== undefined) {
        const running = client;
        client = undefined;
        try {
            await running.stop();
        } catch (error) {
            // The server already exited.
        }
    }
    statedExecutable = executablePath();
    client = await startClient(statedExecutable, (message) => {
        vscode.window.showErrorMessage(message);
    });
}

/// Stops the language client when VS Code closes the extension.
export async function deactivate(): Promise<void> {
    if (client === undefined) { return; }
    const running = client;
    client = undefined;
    await running.stop();
}
