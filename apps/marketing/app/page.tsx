import Link from "next/link";
import type { CSSProperties } from "react";

const PORTFOLIO_URL = "https://helisudani0.github.io/Heli_Sudani-Portfolio/";

const signalTiles = [
  ["North-south capture", "Gateway, laptop, SPAN/TAP, and remote sensor coverage models."],
  ["Behavior graph", "Hosts, destinations, services, baselines, sessions, and sequence transitions."],
  ["Detection fabric", "DNS tunnel defense, C2 cadence, scans, TLS, HTTP abuse, exfil, and IOC matching."],
  ["Evidence vault", "PDF reports, artifacts, host risk, ATT&CK context, and hunt-ready history."]
];

const detectionPlanes = [
  ["DNS tunneling", "Long-query thresholds, subdomain entropy, single-domain frequency, and exfiltration scoring."],
  ["Reconnaissance", "Horizontal scans, vertical sweeps, half-open SYN bursts, service drift, and asset risk."],
  ["Command and control", "Beacon cadence, jitter, suspicious TLS, IRC/P2P fingerprints, and rare sequence transitions."],
  ["Web abuse", "Traversal, SQL injection patterns, automated user agents, oversized POSTs, and base64-heavy payloads."],
  ["Threat intelligence", "Local indicators, IP/domain feeds, Tor context, IOC matching, and reputation-weighted prioritization."],
  ["Investigation evidence", "Session reconstruction, artifacts, host baselines, topology, timelines, and executive PDF reporting."]
];

const missionLanes = [
  ["Install", "Download the Windows sensor control center. No source-code handoff for normal users."],
  ["Start", "The GUI detects the laptop LAN address and starts the analyzer on the right interface."],
  ["Observe", "Live packets become sessions, assets, protocol summaries, and prioritized detections."],
  ["Investigate", "Pivot from alerts to hosts, streams, artifacts, hunts, and evidence packages."],
  ["Expand", "Move from a laptop sensor to gateway, SPAN/TAP, Kubernetes, or distributed collectors."]
];

const coverage = [
  ["Endpoint visibility", "Use the laptop adapter for immediate local capture and analyst validation."],
  ["LAN visibility", "Deploy on a gateway, mirrored switch port, TAP, or routed sensor to observe broader network flows."],
  ["Distributed sensors", "Forward raw packet evidence or normalized context into the collector for multi-host investigations."],
  ["Enterprise storage", "Preserve captures, detections, assets, hunts, and reports with long-term database-backed workflows."]
];

function HolographicNetwork() {
  return (
    <div className="neural-shell relative overflow-hidden rounded-[3rem] border border-white/10 bg-[#040c14] p-6 shadow-[0_40px_140px_rgba(0,0,0,.45)]">
      <div className="depth-grid" />
      <div className="radar-orbit orbit-a" />
      <div className="radar-orbit orbit-b" />
      <div className="radar-orbit orbit-c" />
      <div className="scan-beam" />
      <div className="constellation-line line-a" />
      <div className="constellation-line line-b" />
      <div className="constellation-line line-c" />
      <span className="signal-node node-a" />
      <span className="signal-node node-b" />
      <span className="signal-node node-c" />
      <span className="signal-node node-d" />
      <div className="absolute left-7 top-7 rounded-2xl border border-signal/25 bg-signal/10 px-4 py-3 backdrop-blur-xl">
        <p className="text-[10px] font-black uppercase tracking-[.22em] text-signal">Live mesh</p>
        <p className="mt-1 text-xl font-semibold text-white">Packet intelligence</p>
      </div>
      <div className="absolute bottom-7 left-7 right-7 grid gap-3 md:grid-cols-2">
        {signalTiles.map(([title, detail]) => (
          <div key={title} className="rounded-2xl border border-white/10 bg-black/35 p-4 backdrop-blur-xl">
            <h3 className="text-sm font-black uppercase tracking-[.16em] text-white">{title}</h3>
            <p className="mt-2 text-sm leading-6 text-slate-300">{detail}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Page() {
  return (
    <main className="relative overflow-hidden">
      <section className="relative mx-auto grid max-w-7xl gap-12 px-6 py-24 lg:grid-cols-[.88fr_1.12fr] lg:items-center">
        <div className="absolute -left-24 top-24 h-72 w-72 rounded-full bg-signal/15 blur-[110px]" />
        <div className="relative z-10">
          <div className="inline-flex rounded-full border border-signal/30 bg-signal/10 px-4 py-2 text-xs font-black uppercase tracking-[.25em] text-signal">Enterprise Network Detection And Response</div>
          <h1 className="mt-7 max-w-4xl text-6xl font-semibold leading-[.88] tracking-[-0.08em] text-white md:text-8xl">A command layer for live network defense.</h1>
          <p className="mt-7 max-w-2xl text-xl leading-9 text-slate-300">Ravynel transforms packet capture, distributed sensor visibility, behavioral analytics, and investigation reporting into one installable NDR product for security teams that need clarity fast.</p>
          <p className="mt-5 text-sm font-semibold text-slate-400">
            Developed by{" "}
            <a className="text-white underline decoration-signal/60 underline-offset-4 transition hover:text-signal" href={PORTFOLIO_URL} target="_blank" rel="noreferrer">HeliSudani</a>
          </p>
          <div className="mt-9 flex flex-wrap gap-3">
            <Link href="/download" className="rounded-full bg-gradient-to-r from-signal via-[#7fdcff] to-ember px-6 py-3 font-bold text-ink shadow-[0_18px_70px_rgba(84,216,255,.25)]">Download Windows GUI</Link>
            <Link href="/docs" className="rounded-full border border-white/15 bg-white/[.04] px-6 py-3 font-bold text-white transition hover:border-signal/50 hover:bg-signal/10">View deployment guide</Link>
          </div>
        </div>
        <HolographicNetwork />
      </section>

      <section className="border-y border-white/10 bg-white/[.028] px-6 py-18">
        <div className="mx-auto max-w-7xl">
          <div className="grid gap-5 lg:grid-cols-[.8fr_1.2fr] lg:items-center">
            <div>
              <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Product separation</p>
              <h2 className="mt-4 text-4xl font-semibold tracking-[-0.055em] text-white md:text-5xl">A public product site. A private operations console. No mixed-mode chaos.</h2>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <article className="depth-card rounded-[2rem] p-6">
                <p className="text-xs font-black uppercase tracking-[.18em] text-signal">Website</p>
                <h3 className="mt-3 text-2xl font-semibold text-white">Evaluate, learn, download.</h3>
                <p className="mt-3 leading-7 text-slate-300">The public surface explains features, deployment, documentation, releases, support, and installer packages. It never runs packet capture.</p>
              </article>
              <article className="depth-card rounded-[2rem] p-6">
                <p className="text-xs font-black uppercase tracking-[.18em] text-ember">Installed app</p>
                <h3 className="mt-3 text-2xl font-semibold text-white">Operate, detect, report.</h3>
                <p className="mt-3 leading-7 text-slate-300">The local GUI starts the analyzer, finds the right network URL, and opens a focused analyst console for real telemetry.</p>
              </article>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 py-24">
        <div className="flex flex-col justify-between gap-6 md:flex-row md:items-end">
          <div>
            <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Detection fabric</p>
            <h2 className="mt-4 max-w-3xl text-4xl font-semibold tracking-[-0.055em] text-white md:text-5xl">Signal-rich detection modules without noisy theatrics.</h2>
          </div>
          <Link href="/docs" className="rounded-full border border-white/15 bg-white/[.04] px-5 py-3 text-sm font-bold text-white transition hover:border-signal/50 hover:bg-signal/10">Read detection guide</Link>
        </div>
        <div className="mt-10 grid gap-5 md:grid-cols-2 xl:grid-cols-3">
          {detectionPlanes.map(([title, detail], index) => (
            <article key={title} className="threat-plane group rounded-[2rem] p-6" style={{ animationDelay: `${index * 80}ms` } as CSSProperties}>
              <div className="mb-5 h-1.5 w-16 rounded-full bg-gradient-to-r from-signal to-ember" />
              <h3 className="text-2xl font-semibold tracking-[-.04em] text-white">{title}</h3>
              <p className="mt-4 leading-7 text-slate-300">{detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="mission-shell border-y border-white/10 px-6 py-24">
        <div className="mx-auto max-w-7xl">
          <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Mission flow</p>
          <h2 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.055em] text-white md:text-5xl">From installer to investigation in one clean operator journey.</h2>
          <div className="mt-10 grid gap-4 lg:grid-cols-5">
            {missionLanes.map(([title, detail], index) => (
              <article key={title} className="mission-step rounded-[2rem] p-5">
                <span className="text-xs font-black uppercase tracking-[.18em] text-signal">0{index + 1}</span>
                <h3 className="mt-4 text-2xl font-semibold text-white">{title}</h3>
                <p className="mt-3 leading-7 text-slate-300">{detail}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 py-24">
        <div className="grid gap-10 lg:grid-cols-[.75fr_1.25fr] lg:items-start">
          <div>
            <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Deployment reality</p>
            <h2 className="mt-4 text-4xl font-semibold tracking-[-0.055em] text-white md:text-5xl">See the traffic your sensor can actually observe.</h2>
            <p className="mt-5 leading-8 text-slate-300">A laptop can capture its visible adapter traffic immediately. For full enterprise LAN coverage, place Ravynel where packets traverse: gateways, mirrored ports, TAPs, or distributed collectors.</p>
          </div>
          <div className="grid gap-5 md:grid-cols-2">
            {coverage.map(([title, detail]) => (
              <article key={title} className="rounded-[2rem] border border-white/10 bg-gradient-to-b from-white/[.07] to-white/[.025] p-6 transition hover:border-signal/35">
                <h3 className="text-xl font-semibold text-white">{title}</h3>
                <p className="mt-3 leading-7 text-slate-300">{detail}</p>
              </article>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}


