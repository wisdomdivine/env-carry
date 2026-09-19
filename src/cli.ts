import { Command } from 'commander';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import pc from 'picocolors';
import {
  armorPayload,
  dearmorPayload,
  decryptPayload,
  encryptPayload,
  generatePassphrase,
  EncryptedEnvelope
} from './crypto.js';
import { parseEnv, stringifyEnv } from './parser.js';
import { auditEnvMap, maskSecret, Severity } from './audit/detector.js';
import { scanGitHistoryForSecrets } from './audit/git-scanner.js';
import { checkDrift, findExampleEnvFile } from './drift.js';
import { runWithEnv } from './runner.js';
import { startEphemeralRelay, fetchRelayEnvelope } from './transit/relay.js';

function promptPassword(promptText: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(pc.cyan(`? `) + pc.bold(promptText), (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function printBanner(): void {
  console.log(
    pc.cyan(`\n  📦 `) +
      pc.bold(pc.white('env-carry')) +
      pc.gray(' • Zero-friction, encrypted environment transfer & takeover audits\n')
  );
}

export function createCli(): Command {
  const program = new Command();

  program
    .name('env-carry')
    .description('Zero-friction, end-to-end encrypted environment transfer, drift detection, and takeover audit for developers.')
    .version('1.0.0');

  // --- COMMAND: PACK ---
  program
    .command('pack [file]')
    .description('Encrypt a .env file into a portable .carry file or armor code')
    .option('-p, --passphrase <phrase>', 'Custom passphrase (auto-generated if omitted)')
    .option('-o, --output <path>', 'Output file path (defaults to <file>.carry)')
    .option('--armor', 'Print copy-pasteable carry:// armor string instead of writing file')
    .action(async (file = '.env', options) => {
      printBanner();
      const targetFile = path.resolve(process.cwd(), file);
      if (!fs.existsSync(targetFile)) {
        console.error(pc.red(`✖ File not found: ${file}`));
        process.exit(1);
      }

      const content = fs.readFileSync(targetFile, 'utf8');
      const parsed = parseEnv(content);
      const keyCount = Object.keys(parsed.map).length;

      const passphrase = options.passphrase || generatePassphrase();
      const envelope = encryptPayload(content, passphrase, {
        filename: path.basename(file),
        keyCount
      });

      console.log(pc.green(`✔ Encrypted ${keyCount} environment variables using AES-256-GCM`));
      console.log(
        pc.yellow(`\n🔑 Passphrase: `) +
          pc.bold(pc.bgMagenta(pc.white(` ${passphrase} `)))
      );
      console.log(pc.gray('   (Keep this secret or speak it to your teammate)\n'));

      if (options.armor) {
        const armor = armorPayload(envelope);
        console.log(pc.cyan('📋 Copy-pasteable Armor Code:'));
        console.log(pc.bold(armor));
      } else {
        const outPath = path.resolve(
          process.cwd(),
          options.output || `${file}.carry`
        );
        fs.writeFileSync(outPath, JSON.stringify(envelope, null, 2), 'utf8');
        console.log(pc.green(`✔ Saved encrypted envelope to: `) + pc.bold(path.relative(process.cwd(), outPath)));
      }
    });

  // --- COMMAND: UNPACK ---
  program
    .command('unpack <source>')
    .description('Decrypt a .carry file or carry:// armor string into a .env file')
    .option('-p, --passphrase <phrase>', 'Decryption passphrase')
    .option('-o, --output <path>', 'Destination output file (defaults to .env)')
    .option('--stdout', 'Print decrypted content to stdout instead of writing to disk')
    .action(async (source, options) => {
      printBanner();
      let envelope: EncryptedEnvelope;

      if (source.startsWith('carry://') || source.length > 300) {
        try {
          envelope = dearmorPayload(source);
        } catch (e: any) {
          console.error(pc.red(`✖ Invalid carry armor code: ${e.message}`));
          process.exit(1);
        }
      } else {
        const filePath = path.resolve(process.cwd(), source);
        if (!fs.existsSync(filePath)) {
          console.error(pc.red(`✖ Carry file not found: ${source}`));
          process.exit(1);
        }
        try {
          const raw = fs.readFileSync(filePath, 'utf8');
          envelope = dearmorPayload(raw);
        } catch (e: any) {
          console.error(pc.red(`✖ Failed to parse carry file: ${e.message}`));
          process.exit(1);
        }
      }

      const passphrase =
        options.passphrase || (await promptPassword('Enter decryption passphrase: '));

      try {
        const decrypted = decryptPayload(envelope, passphrase);
        if (options.stdout) {
          console.log(decrypted);
        } else {
          const outPath = path.resolve(
            process.cwd(),
            options.output || envelope.metadata?.filename || '.env'
          );
          fs.writeFileSync(outPath, decrypted, 'utf8');
          console.log(pc.green(`✔ Decrypted successfully into `) + pc.bold(path.relative(process.cwd(), outPath)));
        }
      } catch (err: any) {
        console.error(pc.red(`\n✖ ${err.message}`));
        process.exit(1);
      }
    });

  // --- COMMAND: SEND (EPHEMERAL TRANSIT) ---
  program
    .command('send [file]')
    .description('Send a .env securely via one-shot ephemeral relay or armor code')
    .option('-p, --passphrase <phrase>', 'Custom passphrase')
    .option('--port <port>', 'Local relay port', '0')
    .action(async (file = '.env', options) => {
      printBanner();
      const targetFile = path.resolve(process.cwd(), file);
      if (!fs.existsSync(targetFile)) {
        console.error(pc.red(`✖ File not found: ${file}`));
        process.exit(1);
      }

      const content = fs.readFileSync(targetFile, 'utf8');
      const parsed = parseEnv(content);
      const keyCount = Object.keys(parsed.map).length;
      const passphrase = options.passphrase || generatePassphrase();

      const envelope = encryptPayload(content, passphrase, {
        filename: path.basename(file),
        keyCount
      });

      const armor = armorPayload(envelope);

      console.log(pc.green(`✔ Encrypted ${keyCount} environment variables.`));
      console.log(
        pc.yellow(`\n🔑 Single-Use Passphrase: `) +
          pc.bold(pc.bgMagenta(pc.white(` ${passphrase} `)))
      );

      console.log(pc.cyan(`\nOption A (Instant Armor Code - paste over any channel):`));
      console.log(pc.gray(armor.slice(0, 70) + '... (truncated, run with --armor to see full)'));

      const relay = await startEphemeralRelay(envelope, {
        port: parseInt(options.port, 10)
      });

      console.log(pc.cyan(`\nOption B (Direct Peer-to-Peer Transit):`));
      console.log(
        pc.bold(pc.white(`Run on recipient's machine:\n`)) +
          pc.bgCyan(pc.black(` env-carry receive ${relay.url} `))
      );
      console.log(pc.gray(`\nWaiting for recipient to fetch... (Burn-after-reading enabled)`));

      const result = await relay.done;
      if (result.success) {
        console.log(pc.green(`\n✔ Payload fetched by ${result.remoteIp || 'peer'}.`));
        console.log(pc.magenta(`🔥 Ephemeral relay burned and closed immediately. All clean!`));
      } else {
        console.log(pc.yellow(`\nRelay timed out or was closed.`));
      }
    });

  // --- COMMAND: RECEIVE ---
  program
    .command('receive <target>')
    .description('Receive and decrypt an environment from a relay URL or armor string')
    .option('-p, --passphrase <phrase>', 'Decryption passphrase')
    .option('-o, --output <path>', 'Destination output file (defaults to .env)')
    .action(async (target, options) => {
      printBanner();
      let envelope: EncryptedEnvelope;

      if (target.startsWith('http://') || target.startsWith('https://')) {
        console.log(pc.cyan(`Connecting to ephemeral relay: ${target}...`));
        try {
          envelope = await fetchRelayEnvelope(target);
          console.log(pc.green(`✔ Received encrypted payload from relay.`));
        } catch (err: any) {
          console.error(pc.red(`✖ Relay fetch failed: ${err.message}`));
          process.exit(1);
        }
      } else {
        try {
          envelope = dearmorPayload(target);
        } catch (err: any) {
          console.error(pc.red(`✖ Invalid transfer target: ${err.message}`));
          process.exit(1);
        }
      }

      const passphrase =
        options.passphrase || (await promptPassword('Enter decryption passphrase: '));

      try {
        const decrypted = decryptPayload(envelope, passphrase);
        const outPath = path.resolve(
          process.cwd(),
          options.output || envelope.metadata?.filename || '.env'
        );
        fs.writeFileSync(outPath, decrypted, 'utf8');
        console.log(pc.green(`✔ Successfully saved decrypted environment to: `) + pc.bold(path.relative(process.cwd(), outPath)));
      } catch (err: any) {
        console.error(pc.red(`\n✖ ${err.message}`));
        process.exit(1);
      }
    });

  // --- COMMAND: AUDIT (CODEBASE TAKEOVER) ---
  program
    .command('audit [file]')
    .description('Run a codebase takeover audit: identify secrets, generate rotation guide, and scan git leaks')
    .option('--checklist [path]', 'Export an actionable Markdown rotation checklist (defaults to TAKEOVER_CHECKLIST.md)')
    .action(async (file = '.env', options) => {
      printBanner();
      const targetFile = path.resolve(process.cwd(), file);
      if (!fs.existsSync(targetFile)) {
        console.error(pc.red(`✖ File not found: ${file}`));
        process.exit(1);
      }

      const content = fs.readFileSync(targetFile, 'utf8');
      const parsed = parseEnv(content);
      const findings = auditEnvMap(parsed.map);

      console.log(pc.bold(pc.white(`🔍 Codebase Takeover Audit for: `)) + pc.cyan(file));
      console.log(pc.gray(`Total keys detected: ${Object.keys(parsed.map).length}\n`));

      if (findings.length === 0) {
        console.log(pc.green(`✔ No high-risk or known third-party API secrets detected.`));
        return;
      }

      const severityBadge = (sev: Severity) => {
        switch (sev) {
          case 'CRITICAL':
            return pc.bgRed(pc.white(' CRITICAL '));
          case 'HIGH':
            return pc.bgYellow(pc.black(' HIGH '));
          case 'MEDIUM':
            return pc.bgCyan(pc.black(' MEDIUM '));
          case 'LOW':
            return pc.bgWhite(pc.black(' LOW '));
          default:
            return pc.bgBlue(pc.white(' INFO '));
        }
      };

      console.log(pc.bold('Detected Third-Party Credentials & Risk Level:\n'));
      for (const item of findings) {
        console.log(
          ` ${severityBadge(item.severity)} ${pc.bold(pc.white(item.key))} ` +
            pc.gray(`(${item.service} - ${item.type})`)
        );
        console.log(`   ${pc.gray('Value:')} ${pc.yellow(item.maskedValue)}`);
        console.log(`   ${pc.red('Risk:')} ${item.dangerNotes}`);
        console.log(`   ${pc.cyan('Rotate at:')} ${pc.underline(item.rotationUrl)}`);
        console.log(`   ${pc.green('Action:')} ${item.rotationGuide}\n`);
      }

      // Scan Git History for Leaks
      console.log(pc.bold('Scanning Git history to check if current secrets were ever committed...'));
      const gitLeaks = scanGitHistoryForSecrets(findings);

      if (gitLeaks.length > 0) {
        console.log(
          pc.bgRed(pc.white('\n 🚨 DANGER: SECRETS FOUND IN COMMIT HISTORY! 🚨 \n'))
        );
        for (const leak of gitLeaks) {
          console.log(
            pc.red(` • ${leak.key} (${leak.maskedValue}) was committed in:`) +
              ` ${pc.bold(leak.commitHash)} by ${leak.author} ("${leak.commitMessage}") ${leak.commitDate}`
          );
        }
        console.log(
          pc.yellow(
            `\n ⚠️  These keys MUST be revoked immediately at their respective provider dashboards!`
          )
        );
      } else {
        console.log(pc.green('✔ No active secrets detected in Git commit history.'));
      }

      // Export Checklist if requested or default
      const checklistPath = options.checklist === true || !options.checklist
        ? 'TAKEOVER_CHECKLIST.md'
        : options.checklist;

      const mdLines: string[] = [
        `# Codebase Takeover: Secret Rotation Checklist`,
        `Generated by \`env-carry audit\` on ${new Date().toUTCString()}\n`,
        `> **Critical Rule**: When taking over a codebase, assume previous contributors still retain active credentials. Rotate these keys immediately to prevent unauthorized access or billing abuse.\n`,
        `## 📋 Action Items (${findings.length} Keys Detected)\n`
      ];

      for (const item of findings) {
        mdLines.push(`### [ ] ${item.service}: \`${item.key}\` (${item.severity})`);
        mdLines.push(`- **Key Type**: ${item.type}`);
        mdLines.push(`- **Masked Value**: \`${item.maskedValue}\``);
        mdLines.push(`- **Threat**: ${item.dangerNotes}`);
        mdLines.push(`- **Rotation Link**: [${item.rotationUrl}](${item.rotationUrl})`);
        mdLines.push(`- **Step**: ${item.rotationGuide}\n`);
      }

      if (gitLeaks.length > 0) {
        mdLines.push(`## 🚨 Historic Git Leaks\n`);
        for (const leak of gitLeaks) {
          mdLines.push(`- [ ] **Compromised in Git**: \`${leak.key}\` in commit \`${leak.commitHash}\` (${leak.commitMessage})`);
        }
        mdLines.push('');
      }

      fs.writeFileSync(path.resolve(process.cwd(), checklistPath), mdLines.join('\n'), 'utf8');
      console.log(pc.green(`\n✔ Saved actionable takeover checklist to: `) + pc.bold(checklistPath));
    });

  // --- COMMAND: CHECK (DRIFT DETECTION) ---
  program
    .command('check [file]')
    .description('Check for configuration drift between .env and .env.example')
    .option('-e, --example <path>', 'Path to example template file')
    .action(async (file = '.env', options) => {
      printBanner();
      const targetFile = path.resolve(process.cwd(), file);
      if (!fs.existsSync(targetFile)) {
        console.error(pc.red(`✖ Active env file not found: ${file}`));
        process.exit(1);
      }

      const examplePath =
        options.example || findExampleEnvFile(process.cwd());

      if (!examplePath || !fs.existsSync(examplePath)) {
        console.error(
          pc.red(
            `✖ No example env file found (.env.example, .env.template, etc.). Specify with -e <path>`
          )
        );
        process.exit(1);
      }

      const activeContent = fs.readFileSync(targetFile, 'utf8');
      const exampleContent = fs.readFileSync(examplePath, 'utf8');

      const report = checkDrift(
        activeContent,
        exampleContent,
        path.basename(targetFile),
        path.basename(examplePath)
      );

      console.log(
        pc.bold(pc.white(`Comparing: `)) +
          pc.cyan(report.envPath) +
          pc.gray(` vs `) +
          pc.cyan(report.examplePath) +
          '\n'
      );

      if (report.missingKeys.length > 0) {
        console.log(pc.red(`✖ Missing Keys (defined in template but missing in active env):`));
        for (const k of report.missingKeys) {
          console.log(pc.red(`  - ${k}`));
        }
        console.log('');
      }

      if (report.placeholderKeys.length > 0) {
        console.log(pc.yellow(`⚠️  Unconfigured Placeholders (still has template default):`));
        for (const { key, value } of report.placeholderKeys) {
          console.log(pc.yellow(`  - ${key} = "${value}"`));
        }
        console.log('');
      }

      if (report.emptyKeys.length > 0) {
        console.log(pc.yellow(`⚠️  Empty Keys:`));
        for (const k of report.emptyKeys) {
          console.log(pc.yellow(`  - ${k}=`));
        }
        console.log('');
      }

      if (report.extraKeys.length > 0) {
        console.log(pc.gray(`ℹ Undocumented Keys (in .env but not in template):`));
        for (const k of report.extraKeys) {
          console.log(pc.gray(`  + ${k}`));
        }
        console.log('');
      }

      if (report.isHealthy) {
        console.log(pc.green(`✔ Perfect match! All required keys configured and no placeholders.`));
      } else {
        console.log(pc.red(`✖ Configuration drift detected. Please resolve items above.`));
        process.exitCode = 1;
      }
    });

  // --- COMMAND: SEAL (GIT-NATIVE ENCRYPTED FILE) ---
  program
    .command('seal [file]')
    .description('Encrypt .env into a git-trackable .env.carry file')
    .option('-p, --passphrase <phrase>', 'Encryption passphrase')
    .action(async (file = '.env', options) => {
      printBanner();
      const targetFile = path.resolve(process.cwd(), file);
      if (!fs.existsSync(targetFile)) {
        console.error(pc.red(`✖ File not found: ${file}`));
        process.exit(1);
      }

      const content = fs.readFileSync(targetFile, 'utf8');
      const passphrase =
        options.passphrase || (await promptPassword('Enter encryption passphrase for .env.carry: '));

      const envelope = encryptPayload(content, passphrase, {
        filename: path.basename(file)
      });

      const outPath = path.resolve(process.cwd(), `${file}.carry`);
      fs.writeFileSync(outPath, JSON.stringify(envelope, null, 2), 'utf8');
      console.log(pc.green(`✔ Sealed environment into: `) + pc.bold(path.relative(process.cwd(), outPath)));
      console.log(pc.cyan(`💡 You can safely commit .env.carry to git. Never commit ${file}.`));
    });

  // --- COMMAND: UNSEAL ---
  program
    .command('unseal [file]')
    .description('Decrypt a git-trackable .env.carry file back into .env')
    .option('-p, --passphrase <phrase>', 'Decryption passphrase')
    .action(async (file = '.env.carry', options) => {
      printBanner();
      const targetFile = path.resolve(process.cwd(), file);
      if (!fs.existsSync(targetFile)) {
        console.error(pc.red(`✖ File not found: ${file}`));
        process.exit(1);
      }

      const raw = fs.readFileSync(targetFile, 'utf8');
      const envelope = dearmorPayload(raw);
      const passphrase =
        options.passphrase || (await promptPassword('Enter decryption passphrase: '));

      try {
        const decrypted = decryptPayload(envelope, passphrase);
        const outPath = path.resolve(
          process.cwd(),
          envelope.metadata?.filename || file.replace(/\.carry$/, '') || '.env'
        );
        fs.writeFileSync(outPath, decrypted, 'utf8');
        console.log(pc.green(`✔ Unsealed environment into: `) + pc.bold(path.relative(process.cwd(), outPath)));
      } catch (err: any) {
        console.error(pc.red(`✖ ${err.message}`));
        process.exit(1);
      }
    });

  // --- COMMAND: RUN (IN-MEMORY PROCESS RUNNER) ---
  program
    .command('run')
    .description('Run a command with secrets injected into memory without writing unencrypted .env to disk')
    .option('-f, --file <path>', 'Env source file (.env or .env.carry)', '.env')
    .option('-p, --passphrase <phrase>', 'Passphrase if file is encrypted (.carry)')
    .argument('<command...>', 'Command to execute')
    .action(async (commandArgs, options) => {
      const sourceFile = path.resolve(process.cwd(), options.file);
      let envMap: Record<string, string> = {};

      if (!fs.existsSync(sourceFile)) {
        // Fallback: check if .env.carry exists
        const carryFile = path.resolve(process.cwd(), `${options.file}.carry`);
        if (fs.existsSync(carryFile)) {
          const raw = fs.readFileSync(carryFile, 'utf8');
          const envelope = dearmorPayload(raw);
          const passphrase =
            options.passphrase ||
            process.env.ENV_CARRY_PASSPHRASE ||
            (await promptPassword('Enter passphrase to decrypt env for execution: '));
          const decrypted = decryptPayload(envelope, passphrase);
          envMap = parseEnv(decrypted).map;
        } else {
          console.error(pc.red(`✖ Neither ${options.file} nor ${options.file}.carry found.`));
          process.exit(1);
        }
      } else {
        const content = fs.readFileSync(sourceFile, 'utf8');
        if (sourceFile.endsWith('.carry')) {
          const envelope = dearmorPayload(content);
          const passphrase =
            options.passphrase ||
            process.env.ENV_CARRY_PASSPHRASE ||
            (await promptPassword('Enter passphrase to decrypt env for execution: '));
          const decrypted = decryptPayload(envelope, passphrase);
          envMap = parseEnv(decrypted).map;
        } else {
          envMap = parseEnv(content).map;
        }
      }

      const [executable, ...args] = commandArgs;
      if (!executable) {
        console.error(pc.red('✖ No command specified to run.'));
        process.exit(1);
      }
      const exitCode = await runWithEnv(executable, args, envMap);
      process.exit(exitCode);
    });

  return program;
}
