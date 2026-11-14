#!/usr/bin/env node
// readiness-security — the release-readiness hook "security" (.release-readiness.json,
// hooks.security) for this fork of iDempiere (cogniumhq/idempiere; fork-local, never upstream):
// the candidate's third-party Java artifacts matched against a pinned OSV snapshot of Maven
// advisories, offline.
//
//   node scripts/readiness-security.mjs
//
// What is matched: every group:artifact:version that scripts/readiness-java-deps.mjs reads from
// the repository (the Tycho target platform's Maven locations and the bundles' <artifactItem>
// jars; the same 225 target-platform artifacts as context
// research/idempiere-2026-11-01/baseline/b2-advisories.md). p2 installable units are not Maven
// coordinates, so they are counted and not matched; the line says so.
//
// The snapshot: OSV_MAVEN_DIR, a directory of OSV records (one JSON record per file, or a JSON
// array of records; subdirectories are read too), e.g. OSV's Maven/all.zip unzipped, or the
// Maven snapshot placed by digest (techspec tracks/execution/records/
// osv-snapshots-maven-pypi-2026-11-07.md). The review has no network, so nothing is fetched; the
// hook prints the snapshot's record count, newest `modified` date and a sha256 over its files, so
// the verdict names the data it judged with. OSV_MAVEN_SHA256, when set, must equal that sha256.
//
// A version is affected when it is listed in an affected entry's `versions`, or falls in one of its
// ECOSYSTEM or SEMVER ranges (introduced / fixed / last_affected), in Maven's version order.
// Withdrawn records are skipped. Severity is the record's database_specific.severity (GHSA:
// CRITICAL, HIGH, MODERATE, LOW); a record without one counts as high, as the census pass does.
//
// Exit codes (the release-readiness hook contract): 0 pass, 1 fail, 3 abstain, 2 usage.
//   pass     nothing at the level (SECURITY_LEVEL, default high) or above
//   fail     an artifact has an advisory at the level or above (each is listed), or the
//            snapshot's sha256 is not OSV_MAVEN_SHA256
//   abstain  OSV_MAVEN_DIR is not set, is not a directory, or holds no Maven record
//
// Whenever it matched, the hook prints three figures (no row of record is set; a person may add
// one in a reviewed PR so the count cannot rise):
//   release-readiness:figure advisory_critical <n>      artifacts whose worst advisory is critical
//   release-readiness:figure advisory_high <n>          … is high
//   release-readiness:figure vulnerable_artifacts <n>   artifacts with any advisory
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { compareMaven, inventory, say } from "./readiness-java-deps.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const ORDER = ["low", "moderate", "high", "critical"];
const SEVERITY_ALIASES = { medium: "moderate" };

/** OSV records under dir (sorted by path), with a sha256 over paths and contents. */
export function readSnapshot(dir) {
  const files = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile() && e.name.endsWith(".json")) files.push(p);
    }
  };
  walk(dir);
  files.sort();
  const h = createHash("sha256");
  const records = [];
  let unreadable = 0;
  for (const f of files) {
    const bytes = readFileSync(f);
    h.update(`${relative(dir, f).split(sep).join("/")}\n`);
    h.update(createHash("sha256").update(bytes).digest("hex"));
    h.update("\n");
    let j;
    try {
      j = JSON.parse(bytes.toString("utf8"));
    } catch {
      unreadable++;
      continue;
    }
    for (const r of Array.isArray(j) ? j : [j]) if (r && typeof r === "object" && r.id) records.push(r);
  }
  return { records, files: files.length, unreadable, sha256: h.digest("hex") };
}

function severityOf(rec) {
  const s = String(rec?.database_specific?.severity || "").toLowerCase();
  const n = SEVERITY_ALIASES[s] || s;
  return ORDER.includes(n) ? { level: n, stated: true } : { level: "high", stated: false };
}

/** Is `version` inside one OSV range (events in any order; "0" is the start of time)? */
export function inRange(version, events) {
  const evs = (events || [])
    .map((e) => {
      const [kind, at] = Object.entries(e || {})[0] || [];
      return { kind, at: String(at) };
    })
    .filter((e) => ["introduced", "fixed", "last_affected", "limit"].includes(e.kind));
  evs.sort((a, b) => (a.at === "0" ? -1 : b.at === "0" ? 1 : compareMaven(a.at, b.at)));
  let affected = false;
  for (const e of evs) {
    if (e.kind === "introduced" && (e.at === "0" || compareMaven(version, e.at) >= 0)) affected = true;
    else if (e.kind === "fixed" && compareMaven(version, e.at) >= 0) affected = false;
    else if (e.kind === "last_affected" && compareMaven(version, e.at) > 0) affected = false;
    else if (e.kind === "limit" && compareMaven(version, e.at) >= 0) affected = false;
  }
  return affected;
}

/** Advisory index: "group:artifact" → [{ id, aliases, severity, summary, affected entries }]. */
export function indexMaven(records) {
  const idx = new Map();
  let maven = 0;
  for (const r of records) {
    if (r.withdrawn) continue;
    let counted = false;
    for (const a of r.affected || []) {
      if (a?.package?.ecosystem !== "Maven" || !a.package.name) continue;
      if (!counted) {
        maven++;
        counted = true;
      }
      const k = a.package.name;
      if (!idx.has(k)) idx.set(k, []);
      idx.get(k).push({ rec: r, affected: a });
    }
  }
  return { idx, maven };
}

/** Advisories that affect group:artifact:version. */
export function match(index, group, artifact, version) {
  const out = [];
  for (const { rec, affected } of index.get(`${group}:${artifact}`) || []) {
    const listed = Array.isArray(affected.versions) && affected.versions.includes(version);
    const ranged = (affected.ranges || []).some(
      (rg) => (rg.type === "ECOSYSTEM" || rg.type === "SEMVER") && inRange(version, rg.events),
    );
    if ((listed || ranged) && !out.some((o) => o.id === rec.id)) {
      out.push({ id: rec.id, aliases: rec.aliases || [], ...severityOf(rec) });
    }
  }
  return out.sort((x, y) => ORDER.indexOf(y.level) - ORDER.indexOf(x.level) || x.id.localeCompare(y.id, "en"));
}

export function run({ root = ROOT, env = process.env } = {}) {
  const level = String(env.SECURITY_LEVEL || "high").toLowerCase();
  if (!ORDER.includes(level)) {
    say(`readiness-security: SECURITY_LEVEL '${level}' must be one of ${ORDER.join(", ")}`);
    return 2;
  }
  const inv = inventory(root);
  say(
    `readiness-security: ${inv.maven.length} third-party Maven artifacts (target platform and <artifactItem> jars); ` +
      `${inv.p2.length} p2 units are not Maven coordinates and are not matched`,
  );
  const dir = env.OSV_MAVEN_DIR;
  if (!dir) {
    say("readiness-security: OSV_MAVEN_DIR is not set (no Maven advisory snapshot here); nothing judged");
    return 3;
  }
  try {
    if (!statSync(dir).isDirectory()) throw new Error("not a directory");
  } catch (e) {
    say(`readiness-security: OSV_MAVEN_DIR ${dir} is not a readable directory (${e.message}); nothing judged`);
    return 3;
  }
  const snap = readSnapshot(dir);
  const { idx, maven } = indexMaven(snap.records);
  const newest = snap.records.map((r) => String(r.modified || "")).sort().pop() || "unknown";
  say(
    `readiness-security: snapshot ${snap.files} files, ${maven} Maven records` +
      `${snap.unreadable ? `, ${snap.unreadable} unreadable` : ""}, newest modified ${newest}, sha256 ${snap.sha256}`,
  );
  if (env.OSV_MAVEN_SHA256 && env.OSV_MAVEN_SHA256 !== snap.sha256) {
    say(`readiness-security: FAIL: the snapshot's sha256 is not OSV_MAVEN_SHA256 (${env.OSV_MAVEN_SHA256})`);
    return 1;
  }
  if (maven === 0) {
    say("readiness-security: the snapshot holds no Maven record; nothing judged");
    return 3;
  }
  const min = ORDER.indexOf(level);
  const worst = { critical: 0, high: 0, moderate: 0, low: 0 };
  let vulnerable = 0;
  const failing = [];
  for (const a of inv.maven) {
    const hits = match(idx, a.group, a.artifact, a.version);
    if (!hits.length) continue;
    vulnerable++;
    worst[hits[0].level]++;
    const line =
      `- ${a.group}:${a.artifact}:${a.version} (${hits[0].level}; ${a.sources.join(", ")}): ` +
      hits
        .slice(0, 8)
        .map((h) => `${h.id} ${h.level}${h.stated ? "" : " (no severity stated)"}`)
        .join(", ") +
      (hits.length > 8 ? ` and ${hits.length - 8} more` : "");
    if (ORDER.indexOf(hits[0].level) >= min) failing.push(line);
    else say(line);
  }
  for (const l of failing) say(l);
  say(
    `readiness-security: ${vulnerable} of ${inv.maven.length} artifacts have advisories ` +
      `(worst: ${worst.critical} critical, ${worst.high} high, ${worst.moderate} moderate, ${worst.low} low)`,
  );
  console.log(`release-readiness:figure advisory_critical ${worst.critical}`);
  console.log(`release-readiness:figure advisory_high ${worst.high}`);
  console.log(`release-readiness:figure vulnerable_artifacts ${vulnerable}`);
  if (failing.length) {
    say(`readiness-security: FAIL: ${failing.length} artifact${failing.length === 1 ? "" : "s"} at ${level} or above`);
    return 1;
  }
  say(`readiness-security: nothing at ${level} or above`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length > 2) {
    say("usage: node scripts/readiness-security.mjs (settings come from the environment; see the header)");
    process.exit(2);
  }
  process.exit(run());
}
