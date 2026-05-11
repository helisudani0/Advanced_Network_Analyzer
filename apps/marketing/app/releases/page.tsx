const PORTFOLIO_URL = "https://helisudani0.github.io/Heli_Sudani-Portfolio/";

const releases = [
  {
    version: "0.1.0",
    name: "Enterprise Foundation",
    date: "May 2026",
    status: "Current channel",
    summary: "Foundation release for the separated product website, Windows sensor control center, local analyst console, detection fabric, reporting, and distributed deployment path.",
    highlights: [
      "Windows Sensor Control Center with LAN IP detection, start/stop controls, console launch, folder selection, and log access.",
      "Live analyzer console for detections, assets, sessions, hunts, reports, runtime settings, and capture controls.",
      "Detection fabric for DNS tunneling, port scans, beaconing, exfiltration, suspicious TLS, HTTP anomalies, protocol fingerprints, IOC matching, and behavior baselines.",
      "Go/Rust migration foundation, PostgreSQL/Redis-ready architecture, Kubernetes deployment artifacts, and remote sensor direction.",
      "PDF investigation reporting with host risk, detections, MITRE context, recommendations, and IOC-ready evidence."
    ]
  }
];

const roadmap = [
  ["0.2", "Sensor fleet management", "Installer packaging, signed binaries, remote enrollment, and multi-sensor health views."],
  ["0.3", "Enterprise reporting", "Report templates, scheduled exports, case notes, and compliance-ready evidence packages."],
  ["0.4", "Control plane scale-out", "PostgreSQL/Redis production profile, role-based deployment modes, and hardened collector services."]
];

const quality = [
  ["Channel", "Foundation release"],
  ["Surface", "Website, desktop control center, local analyst console"],
  ["Telemetry", "Observed telemetry only; no synthetic demo events"],
  ["Developed by", "HeliSudani"]
];

export default function ReleasesPage() {
  return (
    <main className="relative overflow-hidden">
      <section className="mx-auto grid max-w-7xl gap-10 px-6 py-24 lg:grid-cols-[.82fr_1.18fr] lg:items-end">
        <div>
          <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Release Notes</p>
          <h1 className="mt-4 text-5xl font-semibold leading-[.96] tracking-[-0.065em] text-white md:text-7xl">Release history written for operators.</h1>
          <p className="mt-6 text-xl leading-9 text-slate-300">Each release note explains the operational impact: what changed, what visibility it unlocks, what deployment surface it affects, and how security teams can use it.</p>
        </div>
        <div className="depth-card rounded-[2rem] p-6">
          <p className="text-xs font-black uppercase tracking-[.2em] text-signal">Release assurance</p>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            {quality.map(([label, value]) => (
              <div key={label} className="rounded-2xl bg-black/20 p-4">
                <p className="text-xs font-black uppercase tracking-[.15em] text-slate-500">{label}</p>
                {label === "Developed by" ? (
                  <a className="mt-2 inline-block font-semibold text-white underline decoration-signal/60 underline-offset-4 transition hover:text-signal" href={PORTFOLIO_URL} target="_blank" rel="noreferrer">{value}</a>
                ) : (
                  <p className="mt-2 font-semibold text-white">{value}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto grid max-w-7xl gap-6 px-6">
        {releases.map((release) => (
          <article key={release.version} className="rounded-[2rem] border border-white/10 bg-white/[.04] p-6">
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/10 pb-5">
              <div>
                <p className="text-sm font-black uppercase tracking-[.2em] text-signal">{release.status}</p>
                <h2 className="mt-2 text-3xl font-semibold tracking-[-.05em] text-white">Ravynel {release.version} - {release.name}</h2>
                <p className="mt-3 max-w-4xl leading-7 text-slate-300">{release.summary}</p>
              </div>
              <span className="rounded-full border border-white/10 bg-white/[.05] px-4 py-2 text-sm font-semibold text-slate-200">{release.date}</span>
            </div>
            <div className="mt-6 grid gap-3 md:grid-cols-2">
              {release.highlights.map((item) => (
                <div key={item} className="rounded-2xl border border-white/10 bg-black/20 p-4 leading-7 text-slate-300">{item}</div>
              ))}
            </div>
          </article>
        ))}
      </section>

      <section className="mission-shell mx-auto mt-14 max-w-7xl rounded-[2rem] border border-signal/25 p-6">
        <div className="flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Forward Path</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-[-.05em] text-white">The product path after foundation.</h2>
          </div>
          <p className="max-w-2xl leading-7 text-slate-300">The roadmap keeps Ravynel moving toward packaged, managed, enterprise-ready network defense while preserving a clean local analyst workflow.</p>
        </div>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {roadmap.map(([version, title, detail]) => (
            <article key={version} className="rounded-2xl bg-black/25 p-5">
              <p className="text-xs font-black uppercase tracking-[.18em] text-signal">Release {version}</p>
              <h3 className="mt-2 text-xl font-semibold text-white">{title}</h3>
              <p className="mt-3 leading-7 text-slate-300">{detail}</p>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}

