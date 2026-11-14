#!/usr/bin/env node
// readiness-sbom-licence — the release-readiness hook "sbom-licence" (.release-readiness.json,
// hooks["sbom-licence"]) for this fork of iDempiere (cogniumhq/idempiere; fork-local, never
// upstream): the candidate's bill of materials and its licences, from the repository alone.
//
//   node scripts/readiness-sbom-licence.mjs
//
//   1. Builds a CycloneDX 1.5 JSON SBOM with one component per
//      - third-party Maven artifact of scripts/readiness-java-deps.mjs (Tycho target platform
//        Maven locations and the bundles' <artifactItem> jars), purl pkg:maven/<g>/<a>@<v>;
//      - p2 installable unit of the target platform (id, version, its repository);
//      - entry of .loop/third-party.json (vendored, copied or generated paths: origin, version,
//        licence as recorded, and the sha256 of every file it matches).
//      No timestamp or random serial, so the same candidate (with the same local Maven
//      repository, step 3) always gives the same SBOM and sha256.
//      Written to SBOM_OUT when set; its sha256 is printed either way.
//   2. Fails when a Maven version is not resolved (missing or still ${…}: the SBOM would be
//      incomplete), when a third-party entry names no licence, or matches no file.
//   3. Licences of the Maven artifacts are read from their POMs in a local Maven repository when
//      one is there (MAVEN_REPO_LOCAL, else ~/.m2/repository): the review has no network, so a POM
//      that is not there is counted as unknown, not fetched. So the SBOM's licence fields and
//      maven_licence_unknown depend on that repository (its path is printed). A third-party
//      licence recorded as "not stated …" is counted as unconfirmed. Neither fails: whether an
//      unknown or unconfirmed licence blocks a release is the owner's call (a row of record with
//      tolerance 0 on the figures below stops the counts from rising).
//
// Prints: release-readiness:figure sbom_components <n>
//         release-readiness:figure third_party_entries <n>
//         release-readiness:figure licence_unconfirmed <n>
//         release-readiness:figure maven_licence_unknown <n>
//
// Exit 0 pass, 1 fail, 2 usage. It never abstains: everything it judges is in the repository.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { inventory, say } from "./readiness-java-deps.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = ".loop/third-party.json";

/** A .gitattributes-style glob (*, ?, [..], **) as a RegExp over repository-relative paths. */
export function globToRegExp(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        const slash = glob[i + 2] === "/";
        re += slash ? "(?:.*/)?" : ".*";
        i += slash ? 2 : 1;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else if (c === "[") {
      const end = glob.indexOf("]", i + 1);
      if (end === -1) re += "\\[";
      else {
        re += `[${glob.slice(i + 1, end).replace(/^!/, "^").replace(/\\/g, "\\\\")}]`;
        i = end;
      }
    } else re += c.replace(/[.+^${}()|\\/]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

export function matcher(entry) {
  if (entry.match === "file") return (p) => p === entry.path;
  if (entry.match === "prefix") return (p) => p.startsWith(entry.path);
  if (entry.match === "glob") {
    const re = globToRegExp(entry.path);
    return (p) => re.test(p);
  }
  return () => false;
}

/** Licence names in a POM's <licenses>, or null when the POM is not in the local repository. */
export function pomLicences(repo, g, a, v) {
  const pom = join(repo, ...g.split("."), a, v, `${a}-${v}.pom`);
  if (!existsSync(pom)) return null;
  const xml = readFileSync(pom, "utf8").replace(/<!--[\s\S]*?-->/g, "");
  const block = xml.match(/<licenses>([\s\S]*?)<\/licenses>/);
  if (!block) return [];
  return [...block[1].matchAll(/<name>\s*([^<]*?)\s*<\/name>/g)].map((m) => m[1]).filter(Boolean);
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

export function build({ root = ROOT, env = process.env } = {}) {
  const inv = inventory(root);
  const problems = [];
  for (const r of inv.unresolved) {
    problems.push(`${r.group}:${r.artifact} has no resolved version (${r.version ?? "none"}; ${r.sources.join(", ")})`);
  }
  const repo = env.MAVEN_REPO_LOCAL || join(homedir(), ".m2", "repository");
  let licenceUnknown = 0;
  const components = [];
  for (const m of inv.maven) {
    const lic = m.version ? pomLicences(repo, m.group, m.artifact, m.version) : null;
    if (!lic || !lic.length) licenceUnknown++;
    const c = {
      type: "library",
      "bom-ref": `pkg:maven/${m.group}/${m.artifact}@${m.version}`,
      group: m.group,
      name: m.artifact,
      version: m.version,
      purl: `pkg:maven/${m.group}/${m.artifact}@${m.version}`,
      properties: m.sources.map((s) => ({ name: "idempiere:source", value: s })),
    };
    if (lic && lic.length) c.licenses = lic.map((name) => ({ license: { name } }));
    components.push(c);
  }
  for (const u of inv.p2) {
    components.push({
      type: "library",
      "bom-ref": `p2:${u.id}@${u.version}`,
      name: u.id,
      version: u.version,
      properties: [
        ...u.repositories.map((r) => ({ name: "idempiere:p2-repository", value: r })),
        ...u.sources.map((s) => ({ name: "idempiere:source", value: s })),
      ],
    });
  }
  const manifest = JSON.parse(readFileSync(join(root, MANIFEST), "utf8"));
  if (!Array.isArray(manifest.entries)) throw new Error(`${MANIFEST} has no entries list`);
  let unconfirmed = 0;
  for (const e of manifest.entries) {
    const files = inv.files.filter(matcher(e));
    const licence = typeof e.licence === "string" ? e.licence.trim() : "";
    if (!licence) problems.push(`${MANIFEST}: ${e.path} names no licence`);
    else if (/^not stated/i.test(licence)) unconfirmed++;
    if (!files.length) problems.push(`${MANIFEST}: ${e.path} (${e.match}) matches no file`);
    components.push({
      type: "file",
      "bom-ref": `third-party:${e.path}`,
      name: e.path,
      version: e.version ?? undefined,
      description: e.origin ?? undefined,
      licenses: licence ? [{ license: { name: licence } }] : undefined,
      hashes: [{ alg: "SHA-256", content: sha256(files.map((f) => `${f} ${sha256(readFileSync(join(root, f)))}\n`).join("")) }],
      properties: [
        { name: "idempiere:third-party-kind", value: String(e.kind ?? "") },
        { name: "idempiere:third-party-match", value: String(e.match) },
        { name: "idempiere:files", value: String(files.length) },
      ],
    });
  }
  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: { component: { type: "application", name: "cogniumhq/idempiere", "bom-ref": "subject" } },
    components,
  };
  return {
    sbom,
    problems,
    counts: {
      maven: inv.maven.length,
      p2: inv.p2.length,
      thirdParty: manifest.entries.length,
      unconfirmed,
      licenceUnknown,
      repo,
      repoPresent: existsSync(repo),
    },
  };
}

export function run({ root = ROOT, env = process.env } = {}) {
  let out;
  try {
    out = build({ root, env });
  } catch (e) {
    say(`readiness-sbom-licence: FAIL: ${e.message}`);
    return 1;
  }
  const { sbom, problems, counts } = out;
  const text = `${JSON.stringify(sbom, null, 2)}\n`;
  if (env.SBOM_OUT) writeFileSync(env.SBOM_OUT, text);
  say(
    `readiness-sbom-licence: CycloneDX 1.5 SBOM: ${sbom.components.length} components ` +
      `(${counts.maven} Maven artifacts, ${counts.p2} p2 units, ${counts.thirdParty} third-party entries), ` +
      `sha256 ${sha256(text)}${env.SBOM_OUT ? `, at ${env.SBOM_OUT}` : ""}`,
  );
  say(
    `readiness-sbom-licence: licences: ${counts.unconfirmed} third-party entries "not stated" (unconfirmed); ` +
      `${counts.licenceUnknown} of ${counts.maven} Maven artifacts with no licence read (no POM in ${counts.repo}` +
      `${counts.repoPresent ? "" : ", which is not there"})`,
  );
  for (const p of problems) say(`- ${p}`);
  console.log(`release-readiness:figure sbom_components ${sbom.components.length}`);
  console.log(`release-readiness:figure third_party_entries ${counts.thirdParty}`);
  console.log(`release-readiness:figure licence_unconfirmed ${counts.unconfirmed}`);
  console.log(`release-readiness:figure maven_licence_unknown ${counts.licenceUnknown}`);
  if (problems.length) {
    say(`readiness-sbom-licence: FAIL: ${problems.length} problem${problems.length === 1 ? "" : "s"}`);
    return 1;
  }
  say("readiness-sbom-licence: every artifact has a version, every third-party entry a licence and a file");
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length > 2) {
    say("usage: node scripts/readiness-sbom-licence.mjs (settings come from the environment; see the header)");
    process.exit(2);
  }
  process.exit(run());
}
