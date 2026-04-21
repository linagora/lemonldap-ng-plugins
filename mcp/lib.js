// Core operations shared by the MCP server (server.js) and the CLI (cli.js).

import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const PROJECT_ROOT =
  process.env.LLNG_PLUGINS_ROOT || path.resolve(__dirname, "..");
export const PLUGINS_DIR = path.join(PROJECT_ROOT, "plugins");
export const LLNG_ROOT = path.join(PROJECT_ROOT, ".llng-test");
export const LLNG_DIR = path.join(LLNG_ROOT, "lemonldap-ng");
export const STATE_DIR = path.join(LLNG_ROOT, "state");
export const LLNG_REPO =
  process.env.LLNG_REPO_URL ||
  "https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng.git";

const COMPONENT_MAP = {
  Common: { dir: "lemonldap-ng-common", libPath: "blib/lib" },
  Portal: { dir: "lemonldap-ng-portal", libPath: "lib" },
  Handler: { dir: "lemonldap-ng-handler", libPath: "lib" },
  Manager: { dir: "lemonldap-ng-manager", libPath: "lib" },
};
const COMPONENT_PRIORITY = ["Portal", "Handler", "Manager", "Common"];

const ASSET_TREES = [
  { src: "portal-templates", dst: ["lemonldap-ng-portal", "site", "templates"] },
  { src: "portal-static", dst: ["lemonldap-ng-portal", "site", "htdocs", "static"] },
  { src: "manager-static", dst: ["lemonldap-ng-manager", "site", "htdocs", "static"] },
];

const TRANSLATIONS_DIR = [
  "lemonldap-ng-portal",
  "site",
  "htdocs",
  "static",
  "languages",
];

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      stdio: ["ignore", "pipe", "pipe"],
      ...opts,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    if (opts.streamStdout) child.stdout.on("data", (d) => process.stdout.write(d));
    if (opts.streamStderr) child.stderr.on("data", (d) => process.stderr.write(d));
    child.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
    child.on("error", (err) =>
      resolve({ code: -1, stdout, stderr: stderr + String(err) }),
    );
  });
}

async function exists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

export async function listPluginDirs() {
  const entries = await fs.readdir(PLUGINS_DIR, { withFileTypes: true });
  return entries
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

async function walkFiles(dir, filter = () => true) {
  const out = [];
  async function walk(current) {
    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(current, e.name);
      if (e.isDirectory()) await walk(p);
      else if (e.isFile() && filter(p, e)) out.push(p);
    }
  }
  await walk(dir);
  return out;
}

function analyzePmPath(libRoot, pmFile) {
  const rel = path.relative(libRoot, pmFile);
  const parts = rel.split(path.sep);
  if (
    parts.length < 4 ||
    parts[0] !== "Lemonldap" ||
    parts[1] !== "NG" ||
    !COMPONENT_MAP[parts[2]]
  ) {
    return null;
  }
  return { topLevel: parts[2], subPath: parts.slice(2).join(path.sep) };
}

async function detectPrimaryComponent(pluginDir) {
  const libRoot = path.join(pluginDir, "lib");
  if (!(await exists(libRoot))) return "Portal";
  const pms = await walkFiles(libRoot, (p) => p.endsWith(".pm"));
  const seen = new Set();
  for (const pm of pms) {
    const info = analyzePmPath(libRoot, pm);
    if (info) seen.add(info.topLevel);
  }
  for (const c of COMPONENT_PRIORITY) if (seen.has(c)) return c;
  return "Portal";
}

function validatePluginName(name) {
  if (typeof name !== "string" || !name) {
    throw new Error(`invalid plugin name: ${JSON.stringify(name)}`);
  }
  if (
    name === "." ||
    name === ".." ||
    name.includes("/") ||
    name.includes("\\") ||
    name.includes("\0") ||
    path.isAbsolute(name)
  ) {
    throw new Error(`invalid plugin name (path separators not allowed): ${name}`);
  }
  const resolved = path.resolve(PLUGINS_DIR, name);
  if (
    resolved !== path.join(PLUGINS_DIR, name) ||
    !resolved.startsWith(PLUGINS_DIR + path.sep)
  ) {
    throw new Error(`invalid plugin name (escapes plugins/): ${name}`);
  }
}

async function readPluginJson(pluginName) {
  validatePluginName(pluginName);
  const p = path.join(PLUGINS_DIR, pluginName, "plugin.json");
  if (!(await exists(p))) return null;
  try {
    return JSON.parse(await fs.readFile(p, "utf8"));
  } catch {
    return null;
  }
}

async function resolveDependencies(root, opts = {}) {
  const { noDeps = false, extra = [] } = opts;
  const visited = new Set();
  const order = [];
  async function visit(name) {
    validatePluginName(name);
    if (visited.has(name)) return;
    visited.add(name);
    if (!(await exists(path.join(PLUGINS_DIR, name)))) {
      throw new Error(`Plugin not found: ${name}`);
    }
    if (!noDeps) {
      const meta = await readPluginJson(name);
      const deps = Array.isArray(meta?.depends) ? meta.depends : [];
      for (const d of deps) await visit(d);
    }
    order.push(name);
  }
  for (const e of extra) await visit(e);
  await visit(root);
  return order;
}

const META_FILE = path.join(STATE_DIR, "_meta.json");

async function readMeta() {
  if (!(await exists(META_FILE))) return {};
  try {
    return JSON.parse(await fs.readFile(META_FILE, "utf8"));
  } catch {
    return {};
  }
}

async function writeMeta(meta) {
  await fs.mkdir(STATE_DIR, { recursive: true });
  await fs.writeFile(META_FILE, JSON.stringify(meta, null, 2) + "\n");
}

async function ensureLlng(log, { ref } = {}) {
  const wantedRef = ref || "";
  const gitDir = path.join(LLNG_DIR, ".git");
  const meta = await readMeta();
  const currentRef = meta.ref ?? null;

  if ((await exists(gitDir)) && currentRef === wantedRef) {
    log.push(
      `LLNG clone already present at ${LLNG_DIR} (ref: ${currentRef || "default"})`,
    );
    return { ref: currentRef, fallback: false };
  }

  if (await exists(LLNG_ROOT)) {
    log.push(
      `Ref change (${currentRef ?? "<none>"} -> ${wantedRef || "default"}); wiping previous clone`,
    );
    await fs.rm(LLNG_ROOT, { recursive: true, force: true });
  }
  await fs.mkdir(LLNG_ROOT, { recursive: true });

  let actualRef = wantedRef;
  let fallback = false;

  if (wantedRef) {
    log.push(`Cloning ${LLNG_REPO} at ref '${wantedRef}' (shallow) ...`);
    const r = await run(
      "git",
      ["clone", "--depth", "1", "--branch", wantedRef, LLNG_REPO, LLNG_DIR],
      { cwd: LLNG_ROOT },
    );
    if (r.code !== 0) {
      log.push(
        `  ref '${wantedRef}' not reachable — falling back to default branch`,
      );
      await fs.rm(LLNG_DIR, { recursive: true, force: true });
      actualRef = "";
      fallback = true;
    }
  }

  if (!actualRef && !(await exists(gitDir))) {
    log.push(`Cloning ${LLNG_REPO} (default branch, shallow) ...`);
    const r = await run(
      "git",
      ["clone", "--depth", "1", LLNG_REPO, LLNG_DIR],
      { cwd: LLNG_ROOT },
    );
    if (r.code !== 0) {
      throw new Error(
        `git clone failed (exit ${r.code}):\n${r.stderr || r.stdout}`,
      );
    }
  }

  await writeMeta({ ref: actualRef });
  log.push(
    `Clone OK (ref: ${actualRef || "default"}${fallback ? " — fallback from " + wantedRef : ""})`,
  );
  return { ref: actualRef, fallback };
}

async function makeCommon(log) {
  log.push("Running `make common` ...");
  const r = await run("make", ["common"], { cwd: LLNG_DIR });
  if (r.code !== 0) {
    throw new Error(
      `make common failed (exit ${r.code}):\n${r.stderr || r.stdout}`,
    );
  }
  log.push("`make common` OK");
}

async function forceSymlink(source, target) {
  try {
    const st = await fs.lstat(target);
    if (st.isSymbolicLink() || st.isFile()) await fs.unlink(target);
    else if (st.isDirectory()) await fs.rm(target, { recursive: true, force: true });
  } catch {
    // no prior entry
  }
  await fs.symlink(source, target);
}

async function linkPluginLib(pluginName, log) {
  const libRoot = path.join(PLUGINS_DIR, pluginName, "lib");
  if (!(await exists(libRoot))) return 0;
  const pms = await walkFiles(libRoot, (p) => p.endsWith(".pm"));
  let n = 0;
  for (const pm of pms) {
    const info = analyzePmPath(libRoot, pm);
    if (!info) continue;
    const { dir, libPath } = COMPONENT_MAP[info.topLevel];
    const target = path.join(LLNG_DIR, dir, libPath, "Lemonldap", "NG", info.subPath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await forceSymlink(pm, target);
    log.push(`  lib: ${path.relative(LLNG_DIR, target)}`);
    n++;
  }
  return n;
}

async function linkPluginTests(pluginName, component, log) {
  const tRoot = path.join(PLUGINS_DIR, pluginName, "t");
  if (!(await exists(tRoot))) return 0;
  const { dir } = COMPONENT_MAP[component];
  const testDir = path.join(LLNG_DIR, dir, "t");
  await fs.mkdir(testDir, { recursive: true });
  const files = await walkFiles(tRoot);
  let n = 0;
  for (const f of files) {
    const rel = path.relative(tRoot, f);
    const target = path.join(testDir, rel);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await forceSymlink(f, target);
    log.push(`  t:   ${path.relative(LLNG_DIR, target)}`);
    n++;
  }
  return n;
}

async function linkPluginAssets(pluginName, log) {
  let n = 0;
  for (const { src, dst } of ASSET_TREES) {
    const srcRoot = path.join(PLUGINS_DIR, pluginName, src);
    if (!(await exists(srcRoot))) continue;
    const dstRoot = path.join(LLNG_DIR, ...dst);
    if (!(await exists(dstRoot))) {
      log.push(`  skip ${src}: ${path.relative(LLNG_DIR, dstRoot)} missing`);
      continue;
    }
    const files = await walkFiles(srcRoot);
    for (const f of files) {
      const rel = path.relative(srcRoot, f);
      const target = path.join(dstRoot, rel);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await forceSymlink(f, target);
      log.push(`  ${src}: ${path.relative(LLNG_DIR, target)}`);
      n++;
    }
  }
  return n;
}

function serializeTranslations(obj) {
  const keys = Object.keys(obj);
  const lines = keys.map((k, i) => {
    const sep = i < keys.length - 1 ? "," : "";
    return `${JSON.stringify(k)}:${JSON.stringify(obj[k])}${sep}`;
  });
  return `{\n${lines.join("\n")}\n}\n`;
}

async function mergeTranslations(pluginName, log) {
  const srcDir = path.join(PLUGINS_DIR, pluginName, "portal-translations");
  if (!(await exists(srcDir))) return 0;
  const dstDir = path.join(LLNG_DIR, ...TRANSLATIONS_DIR);
  if (!(await exists(dstDir))) {
    log.push(`  skip portal-translations: ${dstDir} missing`);
    return 0;
  }

  const stateDir = path.join(STATE_DIR, pluginName);
  await fs.mkdir(stateDir, { recursive: true });
  const stateFile = path.join(stateDir, "translations.json");
  let state = { files: {} };
  if (await exists(stateFile)) {
    try {
      state = JSON.parse(await fs.readFile(stateFile, "utf8"));
      if (!state.files) state.files = {};
    } catch {
      state = { files: {} };
    }
  }

  const files = (await fs.readdir(srcDir)).filter((f) => f.endsWith(".json"));
  let total = 0;
  for (const f of files) {
    const srcJson = JSON.parse(await fs.readFile(path.join(srcDir, f), "utf8"));
    const dstPath = path.join(dstDir, f);
    let dstJson = {};
    if (await exists(dstPath)) {
      dstJson = JSON.parse(await fs.readFile(dstPath, "utf8"));
    }
    // Known keys are tracked as { key -> value-we-last-wrote }. This lets
    // un-merge distinguish "still our key" (current value matches what we
    // wrote) from "upstream took over" (value changed meanwhile). Legacy
    // array form is migrated silently.
    const prev = state.files[f];
    const known = {};
    if (Array.isArray(prev)) {
      for (const k of prev) if (k in dstJson) known[k] = dstJson[k];
    } else if (prev && typeof prev === "object") {
      Object.assign(known, prev);
    }

    for (const [k, v] of Object.entries(srcJson)) {
      if (!(k in dstJson)) {
        dstJson[k] = v;
        known[k] = v;
        total++;
      } else if (
        Object.prototype.hasOwnProperty.call(known, k) &&
        dstJson[k] === known[k]
      ) {
        // Still our key (nobody touched it since we wrote it) — refresh.
        dstJson[k] = v;
        known[k] = v;
      } else if (Object.prototype.hasOwnProperty.call(known, k)) {
        // We added it before, but dstJson no longer matches — upstream or
        // another plugin owns this key now. Relinquish ownership so future
        // un-merge won't clobber their value.
        delete known[k];
      }
      // else: pre-existing core key we never touched — leave it alone.
    }
    state.files[f] = known;
    await fs.writeFile(dstPath, serializeTranslations(dstJson));
    log.push(`  tr:  merged ${Object.keys(known).length} key(s) into ${f}`);
  }
  await fs.writeFile(stateFile, JSON.stringify(state, null, 2));
  return total;
}

async function unmergeTranslations(pluginName) {
  const stateFile = path.join(STATE_DIR, pluginName, "translations.json");
  if (!(await exists(stateFile))) return 0;
  const state = JSON.parse(await fs.readFile(stateFile, "utf8"));
  const dstDir = path.join(LLNG_DIR, ...TRANSLATIONS_DIR);
  let removed = 0;
  for (const [f, entry] of Object.entries(state.files || {})) {
    const dstPath = path.join(dstDir, f);
    if (!(await exists(dstPath))) continue;
    const json = JSON.parse(await fs.readFile(dstPath, "utf8"));
    // Legacy state (array of keys) → blind removal, pre-existing behaviour.
    // New state (object key→value) → only remove when the current value
    // still matches what we wrote, otherwise upstream / another plugin now
    // owns the key and we must not touch it.
    if (Array.isArray(entry)) {
      for (const k of entry) {
        if (k in json) {
          delete json[k];
          removed++;
        }
      }
    } else if (entry && typeof entry === "object") {
      for (const [k, storedValue] of Object.entries(entry)) {
        if (k in json && json[k] === storedValue) {
          delete json[k];
          removed++;
        }
      }
    }
    await fs.writeFile(dstPath, serializeTranslations(json));
  }
  await fs.rm(path.dirname(stateFile), { recursive: true, force: true });
  return removed;
}

export async function prepareTest(
  primary,
  { skipMake = false, with: extra = [], noDeps = false, ref = "" } = {},
) {
  validatePluginName(primary);
  for (const e of extra) validatePluginName(e);
  const log = [];
  const chain = await resolveDependencies(primary, { noDeps, extra });
  const cloneInfo = await ensureLlng(log, { ref });
  if (!skipMake) await makeCommon(log);

  const primaryComponent = await detectPrimaryComponent(
    path.join(PLUGINS_DIR, primary),
  );
  log.push(
    `Plugins to link (in order): ${chain.join(", ")} — primary component: ${primaryComponent}`,
  );

  const totals = { lib: 0, tests: 0, assets: 0, translations: 0 };
  for (const name of chain) {
    log.push(`--- ${name} ---`);
    totals.lib += await linkPluginLib(name, log);
    totals.assets += await linkPluginAssets(name, log);
    totals.translations += await mergeTranslations(name, log);
    if (name === primary) {
      totals.tests += await linkPluginTests(name, primaryComponent, log);
    }
  }

  return {
    primary,
    chain,
    component: primaryComponent,
    ref: cloneInfo.ref || "default",
    refFallback: cloneInfo.fallback,
    totals,
    log,
  };
}

export async function executeTest(
  primary,
  { tests, verbose = true, streamStdio = false } = {},
) {
  validatePluginName(primary);
  const component = await detectPrimaryComponent(
    path.join(PLUGINS_DIR, primary),
  );
  const { dir } = COMPONENT_MAP[component];
  const runDir = path.join(LLNG_DIR, dir);
  if (!(await exists(runDir))) {
    throw new Error(
      `LLNG component dir missing: ${runDir} — run prepare-test first`,
    );
  }

  const args = [];
  if (verbose) args.push("-v");
  args.push(
    "-I.",
    "-I../lemonldap-ng-common/blib/lib",
    "-I../lemonldap-ng-handler/lib",
    "-I../lemonldap-ng-manager/lib",
    "-I../lemonldap-ng-portal/lib",
  );

  const pluginTestDir = path.join(PLUGINS_DIR, primary, "t");
  let targets;
  if (tests && tests.length) {
    targets = tests.map((t) => {
      if (path.isAbsolute(t)) return t;
      if (t === "t" || t.startsWith("t/") || t.startsWith(`t${path.sep}`)) {
        return t;
      }
      return path.join("t", t);
    });
  } else if (await exists(pluginTestDir)) {
    const files = await walkFiles(pluginTestDir, (p) => p.endsWith(".t"));
    targets = files
      .map((f) => path.join("t", path.relative(pluginTestDir, f)))
      .sort();
    if (targets.length === 0) {
      throw new Error(`No .t files found under ${pluginTestDir}`);
    }
  } else {
    throw new Error(`Plugin ${primary} has no t/ directory`);
  }
  args.push(...targets);

  const r = await run("prove", args, {
    cwd: runDir,
    streamStdout: streamStdio,
    streamStderr: streamStdio,
  });
  return {
    plugin: primary,
    component,
    cwd: runDir,
    command: `prove ${args.join(" ")}`,
    exitCode: r.code,
    stdout: r.stdout,
    stderr: r.stderr,
  };
}

async function removeSymlinksUnder(targetPrefix, removed) {
  async function walk(current) {
    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(current, e.name);
      if (e.isSymbolicLink()) {
        try {
          const link = await fs.readlink(p);
          const resolved = path.resolve(current, link);
          if (
            resolved === targetPrefix.slice(0, -1) ||
            resolved.startsWith(targetPrefix)
          ) {
            await fs.unlink(p);
            removed.push(p);
          }
        } catch {
          /* broken link */
        }
      } else if (e.isDirectory()) {
        await walk(p);
      }
    }
  }
  await walk(LLNG_DIR);
}

async function listPluginsWithState() {
  if (!(await exists(STATE_DIR))) return [];
  const entries = await fs.readdir(STATE_DIR, { withFileTypes: true });
  return entries.filter((e) => e.isDirectory()).map((e) => e.name);
}

export async function cleanTest({ plugins } = {}) {
  if (!(await exists(LLNG_DIR))) return { removed: [], unmerged: 0 };
  if (plugins && plugins.length) {
    for (const p of plugins) validatePluginName(p);
  }
  const scope = plugins && plugins.length ? plugins : null;
  const removed = [];
  if (scope) {
    for (const p of scope) {
      await removeSymlinksUnder(path.join(PLUGINS_DIR, p) + path.sep, removed);
    }
  } else {
    await removeSymlinksUnder(PLUGINS_DIR + path.sep, removed);
  }
  let unmerged = 0;
  const targets = scope || (await listPluginsWithState());
  for (const p of targets) {
    unmerged += await unmergeTranslations(p);
  }
  return { removed, unmerged };
}

export async function cleanAll() {
  const pre = await cleanTest();
  let clonedRemoved = false;
  if (await exists(LLNG_ROOT)) {
    await fs.rm(LLNG_ROOT, { recursive: true, force: true });
    clonedRemoved = true;
  }
  return { ...pre, clonedRemoved, llngRoot: LLNG_ROOT };
}
