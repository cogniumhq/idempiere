// Tests for the release-readiness hooks of this fork (fork-local, never upstream):
//   node --test scripts/readiness-hooks.test.mjs
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { compareMaven, inventory, readArtifactItems, readTarget } from "./readiness-java-deps.mjs";
import { inRange, indexMaven, match, run as security } from "./readiness-security.mjs";
import { build, globToRegExp, run as sbomLicence } from "./readiness-sbom-licence.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function quiet(fn) {
  const log = console.log;
  const lines = [];
  console.log = (...a) => lines.push(a.join(" "));
  try {
    return { code: fn(), lines };
  } finally {
    console.log = log;
  }
}

function tmp(t) {
  const d = mkdtempSync(join(tmpdir(), "readiness-hooks-"));
  t.after(() => rmSync(d, { recursive: true, force: true }));
  return d;
}

test("Maven version order", () => {
  const ascending = [
    "1.0-alpha1", "1.0-beta1", "1.0-milestone1", "1.0-rc1", "1.0-SNAPSHOT", "1.0", "1.0-sp1", "1.0.1",
    "1.0.1.v20230101", "1.2", "1.10", "2.0b6", "2.0", "2.15.0-rc1", "2.15.0", "32.0.0-android", "33.4.8-jre",
  ];
  for (let i = 0; i + 1 < ascending.length; i++) {
    assert.equal(compareMaven(ascending[i], ascending[i + 1]), -1, `${ascending[i]} < ${ascending[i + 1]}`);
    assert.equal(compareMaven(ascending[i + 1], ascending[i]), 1, `${ascending[i + 1]} > ${ascending[i]}`);
  }
  for (const [a, b] of [["1.0", "1.0.0"], ["1.0", "1.0-ga"], ["1-final", "1"], ["1.0-cr1", "1.0-rc1"], ["1-a1", "1-alpha-1"], ["1.0.0", "1.0.00"]]) {
    assert.equal(compareMaven(a, b), 0, `${a} = ${b}`);
  }
});

test("OSV ranges: introduced, fixed, last_affected, versions list", () => {
  const fixed = [{ introduced: "0" }, { fixed: "2.15.0" }];
  assert.equal(inRange("2.14.1", fixed), true);
  assert.equal(inRange("2.15.0", fixed), false);
  assert.equal(inRange("2.15.0-rc1", fixed), true);
  const two = [{ introduced: "2.0" }, { fixed: "2.3.1" }, { introduced: "3.0" }, { last_affected: "3.2" }];
  assert.equal(inRange("1.9", two), false);
  assert.equal(inRange("2.3", two), true);
  assert.equal(inRange("2.3.1", two), false);
  assert.equal(inRange("3.2", two), true);
  assert.equal(inRange("3.2.1", two), false);
  const recs = [
    { id: "GHSA-a", database_specific: { severity: "HIGH" }, affected: [{ package: { ecosystem: "Maven", name: "g:a" }, ranges: [{ type: "ECOSYSTEM", events: fixed }] }] },
    { id: "GHSA-b", affected: [{ package: { ecosystem: "Maven", name: "g:a" }, versions: ["9.9"] }] },
    { id: "GHSA-w", withdrawn: "2026-01-01T00:00:00Z", affected: [{ package: { ecosystem: "Maven", name: "g:a" }, versions: ["2.0"] }] },
    { id: "PYSEC-x", affected: [{ package: { ecosystem: "PyPI", name: "g:a" }, versions: ["2.0"] }] },
  ];
  const { idx, maven } = indexMaven(recs);
  assert.equal(maven, 2);
  assert.deepEqual(match(idx, "g", "a", "2.0").map((h) => h.id), ["GHSA-a"]);
  const nine = match(idx, "g", "a", "9.9");
  assert.deepEqual(nine.map((h) => [h.id, h.level, h.stated]), [["GHSA-b", "high", false]]);
  assert.deepEqual(match(idx, "g", "a", "2.15.0"), []);
});

test("inventory: the 225 target-platform artifacts of the B2 baseline, no unresolved version", () => {
  const inv = inventory(ROOT);
  const fromTarget = inv.maven.filter((r) => r.sources.some((s) => s.endsWith(".target")));
  assert.equal(fromTarget.length, 225);
  assert.deepEqual(inv.unresolved, []);
  assert.ok(inv.maven.some((r) => r.group === "com.google.guava" && r.artifact === "guava" && r.version === "33.4.8-jre"));
  assert.ok(!inv.maven.some((r) => r.sources.some((s) => s.startsWith("org.idempiere.test/"))), "test bundle left out");
  assert.ok(inv.p2.length > 0);
});

test("readTarget and readArtifactItems: forms, comments, properties", () => {
  const t = readTarget(
    `<target><locations>
      <!-- <location type="Maven"><groupId>x</groupId><artifactId>y</artifactId><version>1</version></location> -->
      <location includeSource="true" type="Maven"><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version>
        <instructions><![CDATA[<groupId>not</groupId>]]></instructions></location>
      <location type="Maven"><dependencies><dependency><groupId>g2</groupId><artifactId>b</artifactId><version>2</version></dependency>
        <dependency><groupId>g3</groupId><artifactId>c</artifactId><version>3</version></dependency></dependencies></location>
      <location type="InstallableUnit"><unit id="u" version="1.2.3"/><repository location="https://example.invalid/p2"/></location>
    </locations></target>`,
    "x.target",
  );
  assert.deepEqual(t.maven.map((m) => `${m.group}:${m.artifact}:${m.version}`), ["g:a:1.0", "g2:b:2", "g3:c:3"]);
  assert.deepEqual(t.p2, [{ id: "u", version: "1.2.3", repository: "https://example.invalid/p2", source: "x.target" }]);
  const items = readArtifactItems(
    `<project><properties><own.v>4.5</own.v></properties>
      <artifactItem><groupId>g</groupId><artifactId>a</artifactId><version>\${own.v}</version></artifactItem>
      <artifactItem><groupId>g</groupId><artifactId>b</artifactId><version>\${parent.v}</version></artifactItem>
      <artifactItem><groupId>g</groupId><artifactId>c</artifactId><version>\${nobody}</version></artifactItem></project>`,
    "pom.xml",
    new Map([["parent.v", "6"]]),
  );
  assert.deepEqual(items.map((m) => m.version), ["4.5", "6", "${nobody}"]);
});

test("security: abstains without a snapshot, or with no Maven record", (t) => {
  assert.equal(quiet(() => security({ root: ROOT, env: {} })).code, 3);
  const empty = tmp(t);
  writeFileSync(join(empty, "x.json"), JSON.stringify({ id: "PYSEC-1", affected: [{ package: { ecosystem: "PyPI", name: "p" } }] }));
  assert.equal(quiet(() => security({ root: ROOT, env: { OSV_MAVEN_DIR: empty } })).code, 3);
  assert.equal(quiet(() => security({ root: ROOT, env: { OSV_MAVEN_DIR: join(empty, "missing") } })).code, 3);
});

test("security: fails at the level, passes below it, names the snapshot, checks its pin", (t) => {
  const dir = tmp(t);
  mkdirSync(join(dir, "Maven"));
  const rec = (sev) => ({
    id: "GHSA-test-guava",
    modified: "2026-11-06T00:00:00Z",
    summary: "release-readiness:figure advisory_high 0",
    database_specific: { severity: sev },
    affected: [{ package: { ecosystem: "Maven", name: "com.google.guava:guava" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "99.0" }] }] }],
  });
  writeFileSync(join(dir, "Maven", "GHSA-test-guava.json"), JSON.stringify(rec("HIGH")));
  const high = quiet(() => security({ root: ROOT, env: { OSV_MAVEN_DIR: dir } }));
  assert.equal(high.code, 1);
  assert.ok(high.lines.some((l) => l.startsWith("- com.google.guava:guava:33.4.8-jre (high;")));
  assert.ok(high.lines.includes("release-readiness:figure advisory_high 1"));
  assert.ok(high.lines.includes("release-readiness:figure vulnerable_artifacts 1"));
  const sum = high.lines.find((l) => l.includes(" sha256 ")).split(" sha256 ")[1];
  assert.match(sum, /^[0-9a-f]{64}$/);
  assert.equal(quiet(() => security({ root: ROOT, env: { OSV_MAVEN_DIR: dir, OSV_MAVEN_SHA256: sum } })).code, 1);
  assert.equal(quiet(() => security({ root: ROOT, env: { OSV_MAVEN_DIR: dir, OSV_MAVEN_SHA256: "0".repeat(64) } })).code, 1);
  assert.equal(quiet(() => security({ root: ROOT, env: { OSV_MAVEN_DIR: dir, SECURITY_LEVEL: "critical" } })).code, 0);
  writeFileSync(join(dir, "Maven", "GHSA-test-guava.json"), JSON.stringify(rec("MODERATE")));
  const mod = quiet(() => security({ root: ROOT, env: { OSV_MAVEN_DIR: dir } }));
  assert.equal(mod.code, 0);
  assert.ok(mod.lines.includes("release-readiness:figure advisory_high 0"));
  assert.ok(mod.lines.includes("release-readiness:figure vulnerable_artifacts 1"));
  assert.equal(quiet(() => security({ root: ROOT, env: { OSV_MAVEN_DIR: dir, SECURITY_LEVEL: "nope" } })).code, 2);
});

test("sbom-licence: passes on this tree, deterministic, counts the third-party manifest", () => {
  const a = build({ root: ROOT, env: { MAVEN_REPO_LOCAL: "/nonexistent" } });
  const b = build({ root: ROOT, env: { MAVEN_REPO_LOCAL: "/nonexistent" } });
  assert.deepEqual(a.problems, []);
  assert.equal(JSON.stringify(a.sbom), JSON.stringify(b.sbom));
  assert.equal(a.sbom.bomFormat, "CycloneDX");
  assert.equal(a.counts.thirdParty, 64);
  assert.equal(a.counts.maven + a.counts.p2 + a.counts.thirdParty, a.sbom.components.length);
  assert.equal(quiet(() => sbomLicence({ root: ROOT, env: { MAVEN_REPO_LOCAL: "/nonexistent" } })).code, 0);
});

test("sbom-licence: fails on an unresolved version, a missing licence or an entry with no file; reads POM licences", (t) => {
  const root = tmp(t);
  mkdirSync(join(root, ".loop"));
  mkdirSync(join(root, "bundle", "lib"), { recursive: true });
  writeFileSync(join(root, "bundle", "lib", "x.js"), "x");
  writeFileSync(join(root, "bundle", "pom.xml"), "<project><artifactItem><groupId>g</groupId><artifactId>a</artifactId><version>${nobody}</version></artifactItem><artifactItem><groupId>org.ex</groupId><artifactId>ok</artifactId><version>1.0</version></artifactItem></project>");
  const entry = (path, match, licence) => ({ path, match, kind: "vendored", licence });
  writeFileSync(join(root, ".loop", "third-party.json"), JSON.stringify({ entries: [entry("bundle/lib/", "prefix", "MIT"), entry("bundle/lib/*.css", "glob", "MIT"), entry("bundle/lib/x.js", "file", "")] }));
  const repo = join(root, "m2");
  mkdirSync(join(repo, "org", "ex", "ok", "1.0"), { recursive: true });
  writeFileSync(join(repo, "org", "ex", "ok", "1.0", "ok-1.0.pom"), "<project><licenses><license><name>Apache-2.0</name></license></licenses></project>");
  const out = build({ root, env: { MAVEN_REPO_LOCAL: repo } });
  assert.equal(out.problems.length, 3, out.problems.join("\n"));
  assert.ok(out.problems.some((p) => p.includes("g:a has no resolved version")));
  assert.ok(out.problems.some((p) => p.includes("bundle/lib/*.css (glob) matches no file")));
  assert.ok(out.problems.some((p) => p.includes("bundle/lib/x.js names no licence")));
  const ok = out.sbom.components.find((c) => c.purl === "pkg:maven/org.ex/ok@1.0");
  assert.deepEqual(ok.licenses, [{ license: { name: "Apache-2.0" } }]);
  assert.equal(out.counts.licenceUnknown, 1);
  assert.equal(quiet(() => sbomLicence({ root, env: { MAVEN_REPO_LOCAL: repo } })).code, 1);
});

test("glob: .gitattributes rules used by the manifest", () => {
  const re = globToRegExp("org/model/[IX]_*.java");
  assert.ok(re.test("org/model/X_C_Order.java"));
  assert.ok(!re.test("org/model/sub/X_C_Order.java"));
  assert.ok(!re.test("org/model/MOrder.java"));
  const deep = globToRegExp("doc/**/*.html");
  assert.ok(deep.test("doc/a.html") && deep.test("doc/x/y/a.html") && !deep.test("docs/a.html"));
});

test("hook output: a line from data cannot pose as a readiness directive", (t) => {
  const dir = tmp(t);
  writeFileSync(
    join(dir, "r.json"),
    JSON.stringify({ id: "GHSA-x", database_specific: { severity: "LOW" }, affected: [{ package: { ecosystem: "Maven", name: "com.google.guava:guava" }, versions: ["33.4.8-jre"] }] }),
  );
  const out = quiet(() => security({ root: ROOT, env: { OSV_MAVEN_DIR: dir } }));
  assert.equal(out.code, 0);
  assert.equal(out.lines.filter((l) => l.startsWith("release-readiness:figure ")).length, 3);
});
