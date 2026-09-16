import * as path from 'path';
import Mocha from 'mocha';
import { glob } from 'glob';

/// Runs every compiled test file inside the VS Code that loaded the
/// extension. VS Code calls this function and waits on the promise.
export async function run(): Promise<void> {
    const mocha = new Mocha({ ui: 'bdd', color: true, timeout: 60000 });
    const testsRoot = __dirname;

    const files = await glob('**/*.test.js', { cwd: testsRoot });
    for (const file of files.sort()) {
        mocha.addFile(path.resolve(testsRoot, file));
    }

    await new Promise<void>((resolve, reject) => {
        mocha.run((failures) => {
            if (failures > 0) {
                reject(new Error(`${failures} tests failed`));
                return;
            }
            resolve();
        });
    });
}
