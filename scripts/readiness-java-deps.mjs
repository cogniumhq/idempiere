// readiness-java-deps — what this fork of iDempiere ships from others, read from the repository
// alone (no network, no build): the shared part of the release-readiness hooks
// scripts/readiness-security.mjs and scripts/readiness-sbom-licence.mjs. Fork-local
// (cogniumhq/idempiere), never sent upstream.
//
// Three sources, the ones iDempiere's build takes third-party code from:
//   1. Maven locations of the Tycho target platform (every tracked *.target file:
//      <location type="Maven"> with groupId, artifactId, version, or a <dependencies> list);
//   2. maven-dependency-plugin <artifactItem>s in the bundles' pom.xml files (jars copied into a
//      bundle), with ${property} versions resolved from the same pom, then org.idempiere.parent;
//      the test bundle (org.idempiere.test) and coverage-report do not ship and are left out;
//   3. p2 installable units of the target platform (<unit id version>), with their repository.
// Pom <dependency> rows are iDempiere's own modules or Tycho requirements without versions; the
// versions come from the target platform, so they are not listed again.
//
// Also: compareMaven(a, b), Maven's version order (ComparableVersion), for OSV ranges.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const SKIP_DIRS = new Set([".git", "target", "node_modules", ".loop-readiness"]);
/** Bundles that are not part of the product (tests, coverage report). */
export const NOT_SHIPPED = ["org.idempiere.test/", "coverage-report/"];
const PARENT_POM = "org.idempiere.parent/pom.xml";

/** Repository-relative paths of regular files, sorted, skipping build output and .git. */
export function repoFiles(root) {
  const out = [];
  const walk = (dir) => {
    for (const d of readdirSync(dir, { withFileTypes: true })) {
      if (d.isDirectory()) {
        if (!SKIP_DIRS.has(d.name)) walk(join(dir, d.name));
      } else if (d.isFile()) {
        out.push(relative(root, join(dir, d.name)).split(sep).join("/"));
      }
    }
  };
  walk(root);
  return out.sort();
}

const uncomment = (xml) => xml.replace(/<!--[\s\S]*?-->/g, "");
const tag = (block, name) => {
  const m = block.match(new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`));
  return m ? m[1] : null;
};

/** <properties> of a pom, as a map. */
export function pomProperties(xml) {
  const props = new Map();
  const m = uncomment(xml).match(/<properties>([\s\S]*?)<\/properties>/);
  if (!m) return props;
  for (const p of m[1].matchAll(/<([A-Za-z0-9_.-]+)>\s*([^<]*?)\s*<\/\1>/g)) props.set(p[1], p[2]);
  return props;
}

function resolve(value, ...maps) {
  if (value == null) return null;
  return value.replace(/\$\{([^}]+)\}/g, (all, k) => {
    for (const m of maps) if (m.has(k)) return m.get(k);
    return all;
  });
}

/** Maven locations and p2 units of one .target file. */
export function readTarget(xml, file) {
  const maven = [];
  const p2 = [];
  const body = uncomment(xml);
  for (const loc of body.matchAll(/<location\b([^>]*)>([\s\S]*?)<\/location>/g)) {
    const attrs = loc[1];
    const inner = loc[2].replace(/<instructions>[\s\S]*?<\/instructions>/g, "");
    if (/\btype="Maven"/.test(attrs)) {
      const deps = [...inner.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)].map((d) => d[1]);
      for (const b of deps.length ? deps : [inner]) {
        const g = tag(b, "groupId");
        const a = tag(b, "artifactId");
        const v = tag(b, "version");
        if (g && a) maven.push({ group: g, artifact: a, version: v, source: file });
      }
    } else if (/\btype="InstallableUnit"/.test(attrs)) {
      const repo = (inner.match(/<repository\b[^>]*\blocation="([^"]*)"/) || [])[1] || null;
      for (const u of inner.matchAll(/<unit\b[^>]*\bid="([^"]+)"[^>]*\bversion="([^"]+)"/g)) {
        p2.push({ id: u[1], version: u[2], repository: repo, source: file });
      }
    }
  }
  return { maven, p2 };
}

/** <artifactItem>s of one pom, versions resolved from the pom, then the parent's properties. */
export function readArtifactItems(xml, file, parentProps = new Map()) {
  const own = pomProperties(xml);
  const out = [];
  for (const m of uncomment(xml).matchAll(/<artifactItem>([\s\S]*?)<\/artifactItem>/g)) {
    const g = resolve(tag(m[1], "groupId"), own, parentProps);
    const a = resolve(tag(m[1], "artifactId"), own, parentProps);
    const v = resolve(tag(m[1], "version"), own, parentProps);
    if (g && a) out.push({ group: g, artifact: a, version: v, source: file });
  }
  return out;
}

/**
 * The inventory: { maven, p2, unresolved, files }.
 *   maven       one row per group:artifact:version, sorted, with every file that names it
 *   p2          one row per unit id and version, sorted, with its repositories and files
 *   unresolved  Maven rows whose version is missing or still holds ${…}
 */
export function inventory(root) {
  const files = repoFiles(root);
  const shipped = (p) => !NOT_SHIPPED.some((n) => p.startsWith(n));
  let parentProps = new Map();
  try {
    parentProps = pomProperties(readFileSync(join(root, PARENT_POM), "utf8"));
  } catch {
    // no parent pom: ${…} versions stay unresolved and are reported
  }
  const rows = [];
  const units = [];
  for (const f of files.filter(shipped)) {
    if (f.endsWith(".target")) {
      const t = readTarget(readFileSync(join(root, f), "utf8"), f);
      rows.push(...t.maven);
      units.push(...t.p2);
    } else if (f === "pom.xml" || f.endsWith("/pom.xml")) {
      rows.push(...readArtifactItems(readFileSync(join(root, f), "utf8"), f, parentProps));
    }
  }
  const byKey = new Map();
  for (const r of rows) {
    const k = `${r.group}:${r.artifact}:${r.version ?? ""}`;
    const cur = byKey.get(k) || { group: r.group, artifact: r.artifact, version: r.version, sources: [] };
    if (!cur.sources.includes(r.source)) cur.sources.push(r.source);
    byKey.set(k, cur);
  }
  const maven = [...byKey.values()].sort((x, y) =>
    `${x.group}:${x.artifact}:${x.version}`.localeCompare(`${y.group}:${y.artifact}:${y.version}`, "en"),
  );
  const unitKey = new Map();
  for (const u of units) {
    const k = `${u.id}@${u.version}`;
    const cur = unitKey.get(k) || { id: u.id, version: u.version, repositories: [], sources: [] };
    if (u.repository && !cur.repositories.includes(u.repository)) cur.repositories.push(u.repository);
    if (!cur.sources.includes(u.source)) cur.sources.push(u.source);
    unitKey.set(k, cur);
  }
  const p2 = [...unitKey.values()].sort((x, y) => `${x.id}@${x.version}`.localeCompare(`${y.id}@${y.version}`, "en"));
  for (const r of maven) r.sources.sort();
  const unresolved = maven.filter((r) => !r.version || r.version.includes("${"));
  return { maven, p2, unresolved, files };
}

// ---- Maven version order (org.apache.maven.artifact.versioning.ComparableVersion) ----

const QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];
const ALIASES = { ga: "", final: "", release: "", cr: "rc" };
const RELEASE_INDEX = String(QUALIFIERS.indexOf(""));

function comparableQualifier(q) {
  const i = QUALIFIERS.indexOf(q);
  return i === -1 ? `${QUALIFIERS.length}-${q}` : String(i);
}

function stringItem(value, followedByDigit) {
  let v = value;
  if (followedByDigit && v.length === 1) v = { a: "alpha", b: "beta", m: "milestone" }[v] || v;
  v = ALIASES[v] ?? v;
  return { kind: "string", value: v };
}

const isNullItem = (it) =>
  (it.kind === "int" && it.value === 0n) ||
  (it.kind === "string" && comparableQualifier(it.value) === RELEASE_INDEX) ||
  (it.kind === "list" && it.items.length === 0);

function normalize(list) {
  for (let i = list.items.length - 1; i >= 0; i--) {
    const last = list.items[i];
    if (isNullItem(last)) list.items.splice(i, 1);
    else if (last.kind !== "list") break;
  }
}

/** Parse a version into ComparableVersion's item tree (Maven 3.9 rules). */
export function parseMaven(version) {
  const v = String(version).toLowerCase();
  const root = { kind: "list", items: [] };
  let list = root;
  const stack = [list];
  let isDigit = false;
  let start = 0;
  const item = (digit, s) => (digit ? { kind: "int", value: BigInt(s.replace(/^0+(?=\d)/, "")) } : stringItem(s, false));
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (c === ".") {
      list.items.push(i === start ? { kind: "int", value: 0n } : item(isDigit, v.slice(start, i)));
      isDigit = false;
      start = i + 1;
    } else if (c === "-") {
      list.items.push(i === start ? { kind: "int", value: 0n } : item(isDigit, v.slice(start, i)));
      isDigit = false;
      start = i + 1;
      const next = { kind: "list", items: [] };
      list.items.push(next);
      list = next;
      stack.push(list);
    } else if (c >= "0" && c <= "9") {
      if (!isDigit && i > start) {
        // 1.0.0.X1 < 1.0.0-X2: a string qualifier followed by a digit starts a sub-list
        list.items.push(stringItem(v.slice(start, i), true));
        start = i;
        const next = { kind: "list", items: [] };
        list.items.push(next);
        list = next;
        stack.push(list);
      }
      isDigit = true;
    } else {
      if (isDigit && i > start) {
        list.items.push(item(true, v.slice(start, i)));
        start = i;
        const next = { kind: "list", items: [] };
        list.items.push(next);
        list = next;
        stack.push(list);
      }
      isDigit = false;
    }
  }
  if (v.length > start) list.items.push(item(isDigit, v.slice(start)));
  while (stack.length) normalize(stack.pop());
  return root;
}

function cmpItem(a, b) {
  if (b == null) {
    if (a.kind === "int") return a.value === 0n ? 0 : 1;
    if (a.kind === "string") {
      const x = comparableQualifier(a.value);
      return x === RELEASE_INDEX ? 0 : x < RELEASE_INDEX ? -1 : 1;
    }
    for (const it of a.items) {
      const r = cmpItem(it, null);
      if (r !== 0) return r;
    }
    return 0;
  }
  if (a.kind === "int") {
    if (b.kind === "int") return a.value === b.value ? 0 : a.value < b.value ? -1 : 1;
    return 1; // a number is newer than a qualifier or a sub-list
  }
  if (a.kind === "string") {
    if (b.kind === "int") return -1;
    if (b.kind === "string") {
      const x = comparableQualifier(a.value);
      const y = comparableQualifier(b.value);
      return x === y ? 0 : x < y ? -1 : 1;
    }
    return -1;
  }
  if (b.kind === "int") return -1;
  if (b.kind === "string") return 1;
  const n = Math.max(a.items.length, b.items.length);
  for (let i = 0; i < n; i++) {
    const l = a.items[i];
    const r = b.items[i];
    const res = l == null ? (r == null ? 0 : -cmpItem(r, null)) : cmpItem(l, r ?? null);
    if (res !== 0) return res;
  }
  return 0;
}

/** -1, 0 or 1: Maven's order of two version strings. */
export function compareMaven(a, b) {
  return cmpItem(parseMaven(a), parseMaven(b));
}

/** Escape a line that would be read as a readiness directive, drop control characters. */
export function say(line) {
  // eslint-disable-next-line no-control-regex
  const s = String(line).replace(/[\u0000-\u0008\u000b-\u001f\u007f\u001b]/g, "");
  console.log(/^\s*release-readiness:/i.test(s) ? `(escaped) ${s.trim()}` : s);
}
