const sections = [
  ["Desktop control center", "Windows users launch Ravynel through a persistent GUI, not a terminal workflow. The GUI detects the laptop LAN IP, starts the analyzer on the right address, opens the console, and exposes Start, Stop, Refresh, Logs, and folder selection."],
  ["Live capture", "Monitor the default adapter, selected Wi-Fi/Ethernet interfaces, or all local adapters with optional BPF filters. No manual IP entry is required for basic live capture."],
  ["Network-wide visibility", "A laptop adapter sees only traffic visible to that endpoint. For full LAN coverage, deploy Ravynel on a gateway, SPAN/TAP mirror, routed sensor, or distributed collector."],
  ["Detection coverage", "DNS tunneling, beaconing, port scans, suspicious TLS, HTTP anomalies, IRC/P2P fingerprints, exfiltration patterns, IOC matches, reputation scoring, and ML/sequence anomalies."],
  ["Investigation workflow", "Pivot through detections, assets, sessions, artifacts, behavior baselines, saved hunts, topology, and MITRE ATT&CK coverage."],
  ["Reporting", "Generate PDF investigation reports from observed telemetry with host risk, prioritized findings, recommendations, IOC context, and executive summary."],
  ["GeoIP", "GeoIP is optional. Add a MaxMind GeoLite2 City MMDB path in the app settings when country/city enrichment is required."],
  ["Data policy", "Ravynel shows observed telemetry only. Empty tables mean matching packets, assets, artifacts, or detections have not been collected yet."],
];

const commandRefs = [
  ["GUI", "Double-click Ravynel-Launch.pyw from the Windows package."],
  ["Fallback", "Use the packaged Ravynel-Start.cmd only if Windows does not associate .pyw files with Python."],
  ["PCAP replay", "Use the app actions or CLI replay mode for stored packet evidence."],
  ["Sensors", "Use remote raw-packet collectors when capture must happen away from the analyst machine."],
];

export default function DocsPage() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-20">
      <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Documentation</p>
      <h1 className="mt-4 max-w-4xl text-5xl font-semibold leading-[.96] tracking-[-0.065em] text-white md:text-7xl">Deploy Ravynel like a real network sensor.</h1>
      <p className="mt-6 max-w-3xl text-xl leading-9 text-slate-300">Use this guide to deploy the desktop control center, understand capture visibility, configure enrichment, and expand Ravynel from a laptop sensor into broader network coverage.</p>
      <div className="mt-12 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
        {sections.map(([section, detail]) => (
          <article key={section} className="rounded-[2rem] border border-white/10 bg-white/[.04] p-6">
            <h2 className="text-xl font-semibold tracking-[-.03em] text-white">{section}</h2>
            <p className="mt-3 leading-7 text-slate-300">{detail}</p>
          </article>
        ))}
      </div>
      <section className="mt-12 rounded-[2rem] border border-signal/25 bg-signal/10 p-6">
        <h2 className="text-2xl font-semibold text-white">Operator reference</h2>
        <div className="mt-5 grid gap-3 md:grid-cols-2">
          {commandRefs.map(([title, detail]) => (
            <div key={title} className="rounded-2xl bg-black/20 p-4">
              <h3 className="font-semibold text-white">{title}</h3>
              <p className="mt-2 leading-6 text-slate-300">{detail}</p>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}