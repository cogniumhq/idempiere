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
// jars). A row whose version is not resolved is skipped and named (the sbom-licence hook fails on
// it). p2 installable units are not Maven coordinates, so they are counted and not matched; the
// output says so.
//
// The snapshot: OSV_MAVEN_DIR, a directory of OSV records as `unzip Maven/all.zip` leaves it: one
// JSON record per `*.json` file at the top of the directory (subdirectories are not read; other
// files, such as a PROVENANCE file, are not part of it). The review has no network, so nothing is
// fetched. The snapshot's identity is the usual one for offline OSV snapshots:
//   sha256:<hex of sha256 over the lines "<file name>\0<sha256 of the file>\n">, file names sorted
// so the digest it was placed by can be checked. The hook prints it with the record count and the
// newest `modified` date; OSV_MAVEN_SHA256 (with or without "sha256:"), when set, must equal it.
//
// A version is affected when it is listed in an affected entry's `versions`, or falls in one of its
// ECOSYSTEM or SEMVER ranges (introduced / fixed / last_affected), in Maven's version order.
// Withdrawn records are skipped. Severity is the record's database_specific.severity (GitHub
// advisories: CRITICAL, HIGH, MODERATE, LOW); a record without one counts as high (fail closed).
//
// Output: the artifacts with advisories, those below the level first and the worst last, then one
// line naming the failing artifacts worst first, so the verdict's evidence keeps the worst ones.
//
// Exit codes (the release-readiness hook contract): 0 pass, 1 fail, 3 abstain, 2 usage.
//   pass     nothing at the level (SECURITY_LEVEL, default high) or above
//   fail     an artifact has an advisory at the level or above (each is listed), or the
//            snapshot's digest is not OSV_MAVEN_SHA256
//   abstain  OSV_MAVEN_DIR is not set, is not a directory, cannot be read (a `*.json` entry
//            that is not a regular file), or holds no Maven record
//   usage    SECURITY_LEVEL or OSV_MAVEN_SHA256 is malformed
//
// Whenever it matched, the hook prints three figures (no row of record is set; a person may add
// one in a reviewed PR so the count cannot rise):
//   release-readiness:figure advisory_critical <n>      artifacts whose worst advisory is critical
//   release-readiness:figure advisory_high <n>          … is high
//   release-readiness:figure vulnerable_artifacts <n>   artifacts with any advisory
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compareMaven, inventory, say } from "./readiness-java-deps.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const ORDER = ["low", "moderate", "high", "critical"];
const SEVERITY_ALIASES = { medium: "moderate" };

/** The `*.json` record files of a snapshot directory, sorted (no subdirectories). */
export function recordFiles(dir) {
  return readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .sort();
}

/**
 * OSV records of a snapshot directory, and its identity:
 * sha256:<hex> over the sorted "<name>\0<sha256 of file>\n" lines of its `*.json` files.
 * Throws when a `*.json` entry is not a regular file.
 */
export function readSnapshot(dir) {
  const names = recordFiles(dir);
  const lines = [];
  const records = [];
  let unreadable = 0;
  for (const n of names) {
    const p = join(dir, n);
    if (!lstatSync(p).isFile()) throw new Error(`${n} is not a regular file`);
    const bytes = readFileSync(p);
    lines.push(`${n}\0${createHash("sha256").update(bytes).digest("hex")}\n`);
    let r;
    try {
      r = JSON.parse(bytes.toString("utf8"));
    } catch {
      unreadable++;
      continue;
    }
    if (r && typeof r === "object" && typeof r.id === "string") records.push(r);
    else unreadable++;
  }
  const digest = `sha256:${createHash("sha256").update(lines.join("")).digest("hex")}`;
  return { records, files: names.length, unreadable, digest };
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
  let snap;
  try {
    snap = readSnapshot(dir);
  } catch (e) {
    say(`readiness-security: the snapshot in ${dir} cannot be read (${e.message}); nothing judged`);
    return 3;
  }
  const { idx, maven } = indexMaven(snap.records);
  const newest = snap.records.map((r) => String(r.modified || "")).sort().pop() || "unknown";
  say(
    `readiness-security: snapshot ${snap.digest}: ${snap.files} record files, ${maven} Maven records` +
      `${snap.unreadable ? `, ${snap.unreadable} unreadable` : ""}, newest modified ${newest}`,
  );
  const pin = env.OSV_MAVEN_SHA256 ? String(env.OSV_MAVEN_SHA256).trim().toLowerCase() : "";
  if (pin) {
    const want = pin.startsWith("sha256:") ? pin : `sha256:${pin}`;
    if (!/^sha256:[0-9a-f]{64}$/.test(want)) {
      say(`readiness-security: OSV_MAVEN_SHA256 '${env.OSV_MAVEN_SHA256}' is not a sha256 digest`);
      return 2;
    }
    if (want !== snap.digest) {
      say(`readiness-security: FAIL: the snapshot is ${snap.digest}, not the pinned ${want}`);
      return 1;
    }
    say("readiness-security: the snapshot matches OSV_MAVEN_SHA256");
  }
  if (maven === 0) {
    say("readiness-security: the snapshot holds no Maven record; nothing judged");
    return 3;
  }
  const min = ORDER.indexOf(level);
  const worst = { critical: 0, high: 0, moderate: 0, low: 0 };
  const found = [];
  const skipped = [];
  for (const a of inv.maven) {
    if (!a.version || a.version.includes("${")) {
      skipped.push(`${a.group}:${a.artifact}`);
      continue;
    }
    const hits = match(idx, a.group, a.artifact, a.version);
    if (!hits.length) continue;
    worst[hits[0].level]++;
    found.push({ a, hits, rank: ORDER.indexOf(hits[0].level) });
  }
  if (skipped.length) say(`readiness-security: not matched, version not resolved: ${skipped.join(", ")}`);
  // Below the level first, the worst last: the verdict keeps the end of the output.
  found.sort((x, y) => x.rank - y.rank || y.hits.length - x.hits.length);
  for (const { a, hits } of found) {
    say(
      `- ${a.group}:${a.artifact}:${a.version} (${hits[0].level}; ${a.sources.join(", ")}): ` +
        hits
          .slice(0, 8)
          .map((h) => `${h.id} ${h.level}${h.stated ? "" : " (no severity stated)"}`)
          .join(", ") +
        (hits.length > 8 ? ` and ${hits.length - 8} more` : ""),
    );
  }
  const failing = found.filter((f) => f.rank >= min).reverse();
  say(
    `readiness-security: ${found.length} of ${inv.maven.length} artifacts have advisories ` +
      `(worst: ${worst.critical} critical, ${worst.high} high, ${worst.moderate} moderate, ${worst.low} low)`,
  );
  if (failing.length) {
    say(
      `readiness-security: at ${level} or above, worst first: ` +
        failing.map((f) => `${f.a.group}:${f.a.artifact}:${f.a.version} (${f.hits[0].level})`).join(", "),
    );
  }
  console.log(`release-readiness:figure advisory_critical ${worst.critical}`);
  console.log(`release-readiness:figure advisory_high ${worst.high}`);
  console.log(`release-readiness:figure vulnerable_artifacts ${found.length}`);
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
