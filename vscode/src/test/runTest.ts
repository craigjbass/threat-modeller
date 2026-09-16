import * as path from 'path';
import { runTests } from '@vscode/test-electron';

/// Starts a VS Code that loads this extension and runs the test suite in it.
///
/// The run needs no window of its own on macOS. On Linux, start this script
/// under `xvfb-run`, which `scripts/vscode-extension-smoke.sh` does.
async function main(): Promise<void> {
    const extensionDevelopmentPath = path.resolve(__dirname, '../../');
    const extensionTestsPath = path.resolve(__dirname, './suite/index');
    const workspace = path.resolve(extensionDevelopmentPath, 'test-fixtures/project');
    const userDataDirectory = path.resolve(extensionDevelopmentPath, '.vscode-test/user-data');

    await runTests({
        extensionDevelopmentPath,
        extensionTestsPath,
        launchArgs: [
            workspace,
            '--disable-extensions',
            '--disable-gpu',
            '--disable-workspace-trust',
            '--user-data-dir',
            userDataDirectory
        ]
    });
}

main().catch((error) => {
    console.error('the extension tests failed to run:', error);
    process.exit(1);
});
