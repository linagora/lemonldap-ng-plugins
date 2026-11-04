import assert from "node:assert/strict";
import test from "node:test";

import { buildJUnitXml, parseProveOutput, suitesFromProveOutput } from "../junit.js";

const PASS = `t/a.t .. 
1..2
ok 1 - one
ok 2 - two
ok
`;

const FAIL = `t/b.t .. 
1..2
ok 1 - b one
not ok 2 - b two

#   Failed test 'b two'
#   at t/b.t line 3.
# Looks like you failed 1 test of 2.
Dubious, test returned 1 (wstat 256, 0x100)
Failed 1/2 subtests 

Test Summary Report
-------------------
t/b.t (Wstat: 256 (exited 1) Tests: 2 Failed: 1)
Result: FAIL
`;

test("splits one prove stream into one section per .t file", () => {
  const sections = parseProveOutput(PASS + FAIL);
  assert.deepEqual(
    sections.map((s) => s.file),
    ["t/a.t", "t/b.t"],
  );
});

test("turns passing TAP into passing testcases without a phantom case", () => {
  const [suite] = suitesFromProveOutput(PASS, { duration: 0.5 });
  assert.equal(suite.name, "t/a.t");
  assert.deepEqual(
    suite.cases.map((c) => [c.name, c.outcome]),
    [
      ["one", "passed"],
      ["two", "passed"],
    ],
  );
  assert.equal(suite.time, 0.5);
});

test("keeps the failure details and the harness marker", () => {
  const [suite] = suitesFromProveOutput(FAIL, { exitCode: 1, duration: 0.2 });
  assert.deepEqual(
    suite.cases.map((c) => [c.name, c.outcome]),
    [
      ["b one", "passed"],
      ["b two", "failed"],
    ],
  );
  const details = suite.cases[1].details.join("\n");
  assert.match(details, /Failed test 'b two'/);
  assert.match(details, /Dubious, test returned 1/);
});

test("a skipped plan is one skipped case", () => {
  const [suite] = suitesFromProveOutput("t/s.t .. \n1..0 # SKIP no platform\nok\n");
  assert.deepEqual(
    suite.cases.map((c) => [c.name, c.outcome]),
    [["t/s.t", "skipped"]],
  );
});

test("a failed TODO is not a failure", () => {
  const [suite] = suitesFromProveOutput(
    "t/t.t .. \n1..2\nnot ok 1 - later # TODO not yet\nok 2 - now\nok\n",
  );
  assert.deepEqual(
    suite.cases.map((c) => [c.name, c.outcome]),
    [
      ["later", "skipped"],
      ["now", "passed"],
    ],
  );
});

test("a test that dies before its first assertion fails", () => {
  const [suite] = suitesFromProveOutput(
    "t/d.t .. \n# No subtests run\n\nTest Summary Report\n-------------------\n",
    { exitCode: 1 },
  );
  assert.equal(suite.cases.length, 1);
  assert.equal(suite.cases[0].outcome, "failed");
  assert.match(suite.cases[0].details.join("\n"), /No subtests run/);
});

test("prove's own error is captured when no TAP was produced", () => {
  const [suite] = suitesFromProveOutput(
    "Cannot detect source of 't/nope.t'!",
    { name: "t/nope.t", exitCode: 2 },
  );
  assert.equal(suite.name, "t/nope.t");
  assert.equal(suite.cases[0].outcome, "failed");
  assert.match(suite.cases[0].details.join("\n"), /Cannot detect source/);
});

test("the generated XML carries counts, properties and escaped values", () => {
  const suites = [
    ...suitesFromProveOutput(PASS, { duration: 0.1 }),
    ...suitesFromProveOutput(FAIL, { exitCode: 1, duration: 0.2 }),
  ];
  const xml = buildJUnitXml({
    plugin: "demo",
    component: "Portal",
    suites,
    startedAt: new Date("2026-11-04T14:30:05Z"),
    finishedAt: new Date("2026-11-04T14:30:06Z"),
    exitCode: 1,
    properties: { "repo.commit": "abc&def", "repo.dirty": "false" },
  });

  assert.match(xml, /^<\?xml version="1.0" encoding="UTF-8"\?>/);
  assert.match(xml, /<testsuites [^>]*tests="4" failures="1"/);
  assert.match(xml, /<testsuite name="t\/b.t" tests="2" failures="1"/);
  assert.match(xml, /name="repo.commit" value="abc&amp;def"/);
  assert.match(xml, /<failure message="Failed test &apos;b two&apos;"/);
  assert.match(xml, /<system-out><!\[CDATA\[/);
});
