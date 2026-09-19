import { spawn } from 'node:child_process';

/**
 * Spawns a child process with environment variables injected directly into memory.
 * Secrets never touch the disk and disappear when the process exits.
 */
export function runWithEnv(
  executable: string,
  args: string[],
  injectedEnv: Record<string, string>
): Promise<number> {
  return new Promise((resolve, reject) => {
    const combinedEnv = {
      ...process.env,
      ...injectedEnv
    };

    // Use shell on Windows for PATH resolution of .cmd/.bat, direct on Unix
    const useShell = process.platform === 'win32';

    const child = spawn(executable, args, {
      stdio: 'inherit',
      env: combinedEnv,
      shell: useShell
    });

    child.on('error', (err) => {
      reject(err);
    });

    child.on('close', (code) => {
      resolve(code ?? 0);
    });
  });
}
