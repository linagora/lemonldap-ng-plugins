#!/usr/bin/env node
// Thin CLI around lib.js — lets a human (or a script) run the same
// operations the MCP server exposes, without any AI/agent involvement.

import {
  cleanAll,
  cleanTest,
  executeTest,
  listPluginDirs,
  prepareTest,
} from "./lib.js";

const USAGE = `Usage: llng-plugins-test <command> [options]

Commands:
  list                               List plugins available under plugins/
  prepare <plugin> [options]         Clone LLNG + make common + symlink the plugin
  execute <plugin> [-- t1 t2 ...]    Run prove on the plugin (prepare must have run)
  test    <plugin> [options]         prepare + execute in one go
  clean   [plugin [plugin ...]]      Remove symlinks + un-merge translations (scoped or full)
  clean-all                          Remove everything, including the LLNG clone

Options (prepare / test):
  --ref <ref>        Clone LLNG at this git ref (tag or branch).
                     If the ref is missing remotely, falls back to the
                     default branch. Changing ref wipes the previous clone.
  --skip-make        Skip \`make common\` (useful on repeated runs)
  --no-deps          Don't auto-resolve plugin.json "depends"
  --with a,b,c       Also link extra plugins (lib + assets only)
  --quiet            Non-verbose prove (test/execute only)

Examples:
  llng-plugins-test list
  llng-plugins-test test ssh-ca
  llng-plugins-test test ssh-ca --ref v2.23.0
  llng-plugins-test prepare oidc-device-organization --skip-make
  llng-plugins-test execute ssh-ca -- t/01-SSHCA-mycerts.t
  llng-plugins-test clean ssh-ca
  llng-plugins-test clean-all
`;

function parseArgs(argv) {
  const opts = {
    skipMake: false,
    noDeps: false,
    with: [],
    verbose: true,
    ref: "",
  };
  const positional = [];
  let afterDashDash = false;
  const extraTests = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (afterDashDash) {
      extraTests.push(a);
      continue;
    }
    if (a === "--") {
      afterDashDash = true;
    } else if (a === "--skip-make") {
      opts.skipMake = true;
    } else if (a === "--no-deps") {
      opts.noDeps = true;
    } else if (a === "--quiet") {
      opts.verbose = false;
    } else if (a === "--ref") {
      const v = argv[++i];
      if (v === undefined) throw new Error("--ref requires a value");
      opts.ref = v;
    } else if (a.startsWith("--ref=")) {
      opts.ref = a.slice("--ref=".length);
    } else if (a === "--with") {
      const v = argv[++i];
      if (!v) throw new Error("--with requires a value (comma-separated list)");
      opts.with = v.split(",").map((s) => s.trim()).filter(Boolean);
    } else if (a.startsWith("--with=")) {
      opts.with = a
        .slice("--with=".length)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (a === "-h" || a === "--help") {
      opts.help = true;
    } else if (a.startsWith("--")) {
      throw new Error(`Unknown option: ${a}`);
    } else {
      positional.push(a);
    }
  }
  return { positional, opts, extraTests };
}

function fmt(obj) {
  return JSON.stringify(obj, null, 2);
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") {
    process.stdout.write(USAGE);
    return 0;
  }

  const [cmd, ...rest] = argv;
  let parsed;
  try {
    parsed = parseArgs(rest);
  } catch (e) {
    process.stderr.write(`${e.message}\n\n${USAGE}`);
    return 2;
  }
  const { positional, opts, extraTests } = parsed;

  switch (cmd) {
    case "list": {
      const plugins = await listPluginDirs();
      for (const p of plugins) process.stdout.write(`${p}\n`);
      return 0;
    }

    case "prepare": {
      const plugin = positional[0];
      if (!plugin) {
        process.stderr.write("prepare: missing plugin name\n");
        return 2;
      }
      const res = await prepareTest(plugin, {
        skipMake: opts.skipMake,
        noDeps: opts.noDeps,
        with: opts.with,
        ref: opts.ref,
      });
      for (const line of res.log) process.stdout.write(`${line}\n`);
      const refBadge = res.refFallback
        ? `${res.ref} (fallback from '${opts.ref}')`
        : res.ref;
      process.stdout.write(
        `\nOK — primary=${res.primary} ref=${refBadge} component=${res.component} chain=[${res.chain.join(", ")}] ` +
          `links: lib=${res.totals.lib} tests=${res.totals.tests} assets=${res.totals.assets} translations=${res.totals.translations}\n`,
      );
      return 0;
    }

    case "execute": {
      const plugin = positional[0];
      if (!plugin) {
        process.stderr.write("execute: missing plugin name\n");
        return 2;
      }
      const tests = extraTests.length ? extraTests : positional.slice(1);
      const res = await executeTest(plugin, {
        tests: tests.length ? tests : undefined,
        verbose: opts.verbose,
        streamStdio: true,
      });
      // prove output was streamed live; just report the summary line
      process.stdout.write(
        `\n--- prove exit=${res.exitCode} (cwd=${res.cwd})\n`,
      );
      return res.exitCode === 0 ? 0 : 1;
    }

    case "test": {
      const plugin = positional[0];
      if (!plugin) {
        process.stderr.write("test: missing plugin name\n");
        return 2;
      }
      const prep = await prepareTest(plugin, {
        skipMake: opts.skipMake,
        noDeps: opts.noDeps,
        with: opts.with,
        ref: opts.ref,
      });
      for (const line of prep.log) process.stdout.write(`${line}\n`);
      process.stdout.write("\n");
      const tests = extraTests.length ? extraTests : positional.slice(1);
      const res = await executeTest(plugin, {
        tests: tests.length ? tests : undefined,
        verbose: opts.verbose,
        streamStdio: true,
      });
      process.stdout.write(`\n--- prove exit=${res.exitCode}\n`);
      return res.exitCode === 0 ? 0 : 1;
    }

    case "clean": {
      const scope = positional.length ? positional : undefined;
      const res = await cleanTest({ plugins: scope });
      process.stdout.write(fmt({
        removedCount: res.removed.length,
        translationKeysRemoved: res.unmerged,
      }) + "\n");
      return 0;
    }

    case "clean-all": {
      const res = await cleanAll();
      process.stdout.write(fmt({
        removedCount: res.removed.length,
        translationKeysRemoved: res.unmerged,
        clonedRemoved: res.clonedRemoved,
        llngRoot: res.llngRoot,
      }) + "\n");
      return 0;
    }

    default:
      process.stderr.write(`Unknown command: ${cmd}\n\n${USAGE}`);
      return 2;
  }
}

main().then(
  (code) => process.exit(code ?? 0),
  (err) => {
    process.stderr.write(`${err.stack || err.message || err}\n`);
    process.exit(1);
  },
);
