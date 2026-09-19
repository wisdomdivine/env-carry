import { execSync } from 'node:child_process';

export interface GitLeakMatch {
  key: string;
  maskedValue: string;
  commitHash: string;
  author: string;
  commitMessage: string;
  commitDate: string;
}

/**
 * Checks if a git repository exists in the current or ancestor working directories.
 */
export function isGitRepo(cwd: string = process.cwd()): boolean {
  try {
    execSync('git rev-parse --is-inside-work-tree', {
      cwd,
      stdio: 'pipe'
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Searches git commit history to detect if any of the provided active secrets
 * were committed in plaintext in the past.
 */
export function scanGitHistoryForSecrets(
  secrets: Array<{ key: string; rawValue: string; maskedValue: string }>,
  cwd: string = process.cwd()
): GitLeakMatch[] {
  if (!isGitRepo(cwd)) {
    return [];
  }

  const leaks: GitLeakMatch[] = [];

  for (const secret of secrets) {
    // Only search for substantial secrets to avoid false positives (min length 10)
    if (!secret.rawValue || secret.rawValue.length < 10) continue;

    try {
      // Escape for bash/git log pickaxe (-S)
      // Using -S looks for commits that changed the number of occurrences of the string
      const escapedVal = secret.rawValue.replace(/'/g, "'\\''");
      const cmd = `git log -S '${escapedVal}' -n 1 --format="%h|%an|%s|%cr"`;
      
      const stdout = execSync(cmd, {
        cwd,
        stdio: ['pipe', 'pipe', 'ignore'],
        encoding: 'utf8'
      }).trim();

      if (stdout) {
        const [commitHash, author, commitMessage, commitDate] = stdout.split('|');
        leaks.push({
          key: secret.key,
          maskedValue: secret.maskedValue,
          commitHash: commitHash || 'unknown',
          author: author || 'unknown',
          commitMessage: commitMessage || 'unknown',
          commitDate: commitDate || 'unknown'
        });
      }
    } catch {
      // Git command failed or string contains invalid characters, ignore
    }
  }

  return leaks;
}
