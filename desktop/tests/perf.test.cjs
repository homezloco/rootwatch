// perf.cjs parser tests — pure functions, no fixtures needed.
const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  parseBlame,
  parseBootTotal,
  parseBootPhases,
  parseDockerDf,
  parseJournalMb,
  parseAutoremove,
  parseResidualPackages,
  parseDuBytes,
  parseListTimersJson,
  parseTimerShow,
  parseTimerUnitFiles,
  parsePressure,
  throttleDelta,
  stackDupes,
} = require("../perf.cjs");

test("parseBootTotal + phases split the Startup finished line", () => {
  const out =
    "Startup finished in 4.231s (firmware) + 1.203s (loader) + 5.430s (kernel) + 12.345s (userspace) = 23.211s.";
  assert.equal(parseBootTotal(out), 23.211);
  assert.deepEqual(parseBootPhases(out), {
    firmware: 4.231,
    loader: 1.203,
    kernel: 5.43,
    userspace: 12.345,
  });
});

test("parseBlame sums compound 1min times", () => {
  const out = parseBlame("1min 4.008s snapd.service\n  800ms a.service\n");
  assert.equal(out[0].seconds, 64.01);
  assert.equal(out[0].unit, "snapd.service");
  assert.equal(out[1].seconds, 0.8);
});

test("parseDockerDf strips the reclaimable percent suffix", () => {
  const out = parseDockerDf(
    "TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE\nImages          8         2         2.5GB     1.8GB (72%)\n",
  );
  assert.deepEqual(out, [{ type: "Images", total: "8", reclaimable: "1.8GB" }]);
});

test("parseJournalMb / autoremove / residual / duBytes", () => {
  assert.equal(
    parseJournalMb("Archived and active journals take up 512.0M in the file system."),
    512,
  );
  assert.deepEqual(parseAutoremove("Remv libfoo [1.0]\nPurg x [2]\n"), ["libfoo"]);
  assert.deepEqual(parseResidualPackages("ii  keep 1.0 amd64 d\nrc  dead 2.0 amd64 d\n"), ["dead"]);
  assert.equal(parseDuBytes(""), null);
  assert.equal(parseDuBytes("1048576\t/x"), 1048576);
});

test("timer parsers — json path plus show fallback incl. date strings", () => {
  const json = parseListTimersJson(
    JSON.stringify([{ unit: "a.timer", activates: "a.service", next: 1790996400000000, last: 0 }]),
  );
  assert.equal(json[0].next, new Date(1790996400000).toISOString());
  assert.equal(json[0].last, null);

  const map = parseTimerUnitFiles("a.timer enabled\n");
  const show = parseTimerShow(
    "Id=a.timer\nActiveState=active\nNextElapseUSecRealtime=Fri 2026-10-02 20:32:49 PDT\nLastTriggerUSec=0\nTriggers=a.service\n\n",
    map,
  );
  assert.equal(show[0].enabled, "enabled");
  assert.ok(show[0].next); // date-string form still yields a timestamp
  assert.equal(show[0].last, null);
});

test("throttleDelta — first sample null, reset null, zero is zero", () => {
  assert.equal(throttleDelta(null, { at: 1, packageTimeMs: 5 }), null);
  assert.equal(throttleDelta({ at: 0, packageTimeMs: 9 }, { at: 60_000, packageTimeMs: 1 }), null);
  assert.deepEqual(throttleDelta({ at: 0, packageTimeMs: 1 }, { at: 60_000, packageTimeMs: 1 }), {
    deltaMs: 0,
    windowSec: 60,
  });
});

test("parsePressure + stackDupes basics", () => {
  const p = parsePressure("some avg10=2.5 avg60=1 avg300=0 total=1\n");
  assert.equal(p.some10, 2.5);
  assert.equal(p.full10, null); // cpu has no full line
  assert.equal(parsePressure(""), null);
  assert.deepEqual(
    stackDupes(["cups\t2.4.7"], [{ name: "cups", version: "2.4.10" }])[0].name,
    "cups",
  );
});
