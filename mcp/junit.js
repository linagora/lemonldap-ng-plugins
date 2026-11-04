// Turn `prove` output into a JUnit XML report.
//
// The report is meant to be published as a CI artifact: one file per
// plugin/LLNG-ref test run, named after the commit under test and the run
// timestamp, so a certification document can point at it.
//
// We deliberately parse the TAP stream ourselves instead of depending on
// TAP::Formatter::JUnit (Moose, XML::Generator, ...): this keeps `prove`
// transportable and lets us keep its normal console output in the job log.

const HARNESS_FAILURES = [
  /^Dubious, test returned/m,
  /^Failed \d+\/\d+ subtests/m,
  /^# Looks like you (?:failed|planned|died)/m,
  /^#?\s*No subtests run/m,
  /^Parse errors?:/m,
];

const SUMMARY_START =
  /^(?:Test Summary Report|Files=\d+,\s*Tests=|Result: (?:PASS|FAIL)|All tests successful\.?$)/;

function escapeXml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function cdata(value) {
  return `<![CDATA[${String(value ?? "").replace(/]]>/g, "]]]]><![CDATA[>")}]]>`;
}

function splitDirective(text) {
  const m = text.match(/^(.*?)\s+#\s*(TODO|SKIP)\b(.*)$/i);
  if (!m) return { text: text.trim(), directive: null };
  return { text: m[1].trim(), directive: m[2].toUpperCase() };
}

// `prove -v --merge` prints one `t/foo.t .. ` header per test file, then the
// raw TAP, then (for failures) a summary. Split that stream back into files.
export function parseProveOutput(output) {
  const sections = [];
  let current = null;
  let inSummary = false;

  const finish = () => {
    if (!current) return;
    current.raw = [current.header, ...current.lines].join("\n").trimEnd();
    sections.push(current);
    current = null;
  };

  for (const line of String(output ?? "").split(/\r?\n/)) {
    if (SUMMARY_START.test(line)) {
      inSummary = true;
      finish();
      continue;
    }
    if (inSummary) continue;

    const header = line.match(/^(\S+\.t) \.\.\s*(.*)$/);
    if (header) {
      finish();
      current = { file: header[1], tail: header[2].trim(), lines: [], header: line };
      continue;
    }
    if (current) current.lines.push(line);
  }
  finish();
  return sections;
}

function casesFromSection(section) {
  const cases = [];
  let current = null;

  for (const line of section.lines) {
    // `prove -v` ends each file with a bare `ok` (the harness's own success
    // line). It is not a test: without this, every file would grow a
    // phantom "test N" case.
    if (/^ok\s*$/.test(line)) {
      current = null;
      continue;
    }

    const m = line.match(/^(not ok|ok)\b\s*(\d+)?\s*(?:-\s*)?(.*)$/);
    if (m) {
      const [, status, number, rest] = m;
      const { text, directive } = splitDirective(rest);
      let outcome = status === "ok" ? "passed" : "failed";
      if (directive === "SKIP") outcome = "skipped";
      // A failed TODO is expected and therefore not a failure.
      if (directive === "TODO" && status === "not ok") outcome = "skipped";

      current = {
        name: text || `test ${number ?? cases.length + 1}`,
        number: number ? Number(number) : null,
        outcome,
        details: [],
      };
      cases.push(current);
      continue;
    }

    // A plan line ends the diagnostics of the previous test.
    if (/^\d+\.\.\d+/.test(line)) {
      current = null;
      continue;
    }
    if (current) current.details.push(line);
  }

  return cases;
}

function failureMessage(testCase) {
  if (testCase.message) return testCase.message;
  const details = testCase.details.join("\n").trim();
  const explicit = details.match(/^#\s+Failed test .*$/m);
  if (explicit) return explicit[0].replace(/^#\s+/, "");
  return `not ok ${testCase.number ?? ""}`.trim();
}

function suiteFromSection(section, { exitCode = 0, duration = 0 } = {}) {
  const raw = section.raw || "";
  const cases = casesFromSection(section);
  const harnessFailure = HARNESS_FAILURES.some((re) => re.test(raw));
  const plannedSkip = section.lines.some(
    (l) => /^\d+\.\.\d+\s*#\s*(?:SKIP|TODO)\b/i.test(l),
  );

  if (cases.length === 0) {
    const skipped = plannedSkip && !harnessFailure;
    const failed = !skipped && (harnessFailure || exitCode !== 0);
    cases.push({
      name: section.file,
      number: null,
      outcome: skipped ? "skipped" : failed ? "failed" : "passed",
      message: failed
        ? harnessFailure
          ? "harness failure: no test output"
          : `prove exited with status ${exitCode}`
        : undefined,
      details: failed ? [raw] : [],
    });
  } else if (
    (harnessFailure || exitCode !== 0) &&
    !cases.some((c) => c.outcome === "failed")
  ) {
    // The harness itself noticed a problem (plan mismatch, test died before
    // its first assertion, ...): without this, the report would look green.
    cases.push({
      name: `${section.file} (harness)`,
      number: null,
      outcome: "failed",
      message: harnessFailure ? "harness failure" : `prove exited with status ${exitCode}`,
      details: [section.tail, raw].filter(Boolean),
    });
  }

  return {
    name: section.file,
    cases,
    raw,
    time: duration,
  };
}

// Build one suite per .t file. `duration` is the wall-clock time of the
// prove invocation that produced `output`; it is shared when one invocation
// covered several files (e.g. a directory target).
export function suitesFromProveOutput(output, opts = {}) {
  const sections = parseProveOutput(output);
  if (sections.length === 0) {
    return [
      suiteFromSection(
        {
          file: opts.name || "prove",
          tail: "",
          lines: [],
          raw: String(output ?? "").trim(),
        },
        opts,
      ),
    ];
  }
  const each = sections.length ? (opts.duration || 0) / sections.length : 0;
  // An exit status only describes the whole invocation. When it covered
  // several files, use the TAP/harness markers to judge each one instead of
  // painting every suite red.
  const exitCode = sections.length === 1 ? opts.exitCode : 0;
  return sections.map((section) =>
    suiteFromSection(section, { ...opts, exitCode, duration: each }),
  );
}

function count(suites) {
  let tests = 0;
  let failures = 0;
  let skipped = 0;
  for (const suite of suites) {
    tests += suite.cases.length;
    failures += suite.cases.filter((c) => c.outcome === "failed").length;
    skipped += suite.cases.filter((c) => c.outcome === "skipped").length;
  }
  return { tests, failures, skipped };
}

function propertiesXml(properties) {
  const entries = Object.entries(properties).filter(([, v]) => v !== undefined && v !== "");
  if (entries.length === 0) return "";
  const lines = entries.map(
    ([k, v]) => `      <property name="${escapeXml(k)}" value="${escapeXml(v)}"/>`,
  );
  return `    <properties>\n${lines.join("\n")}\n    </properties>\n`;
}

function testCaseXml(testCase, className) {
  const attrs = `classname="${escapeXml(className)}" name="${escapeXml(testCase.name)}" time="0"`;
  if (testCase.outcome === "passed") return `    <testcase ${attrs}/>`;

  if (testCase.outcome === "skipped") {
    return `    <testcase ${attrs}>\n      <skipped/>\n    </testcase>`;
  }

  const details = testCase.details.join("\n").trim();
  return (
    `    <testcase ${attrs}>\n` +
    `      <failure message="${escapeXml(failureMessage(testCase))}" type="Test::More">${cdata(details)}</failure>\n` +
    `    </testcase>`
  );
}

function suiteXml(suite, { className, properties, timestamp }) {
  const totals = count([suite]);
  const body = [
    propertiesXml(properties),
    ...suite.cases.map((c) => `${testCaseXml(c, className)}\n`),
    suite.raw
      ? `    <system-out>${cdata(suite.raw)}</system-out>\n`
      : "",
  ].join("");

  return (
    `  <testsuite name="${escapeXml(suite.name)}" tests="${totals.tests}" ` +
    `failures="${totals.failures}" errors="0" skipped="${totals.skipped}" ` +
    `time="${suite.time.toFixed(3)}" timestamp="${escapeXml(timestamp)}">\n` +
    body +
    `  </testsuite>\n`
  );
}

export function buildJUnitXml({
  name = "lemonldap-ng-plugins",
  plugin,
  component,
  suites,
  properties = {},
  startedAt = new Date(),
  finishedAt = new Date(),
  exitCode = 0,
}) {
  const totals = count(suites);
  const timestamp = startedAt.toISOString();
  const time = Math.max(0, (finishedAt - startedAt) / 1000);
  const className = component ? `${plugin}.${component}` : plugin;
  const allProperties = {
    plugin,
    component,
    exit_code: exitCode,
    ...properties,
  };

  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<testsuites name="${escapeXml(name)}" tests="${totals.tests}" ` +
    `failures="${totals.failures}" errors="0" skipped="${totals.skipped}" ` +
    `time="${time.toFixed(3)}" timestamp="${escapeXml(timestamp)}">\n` +
    suites
      .map((suite) =>
        suiteXml(suite, {
          className,
          properties: allProperties,
          timestamp,
        }),
      )
      .join("") +
    `</testsuites>\n`
  );
}
