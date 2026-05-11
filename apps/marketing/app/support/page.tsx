const PORTFOLIO_URL = "https://helisudani0.github.io/Heli_Sudani-Portfolio/";

const supportTracks = [
  ["Sensor deployment", "Plan where Ravynel should observe traffic: endpoint adapter, Wi-Fi/Ethernet laptop, gateway, SPAN/TAP mirror, or distributed collector."],
  ["Capture readiness", "Validate Npcap, administrator permissions, adapter visibility, BPF filters, and firewall access for same-network console use."],
  ["Detection tuning", "Tune alert volume, profiles, model settings, IOC feeds, GeoIP enrichment, and baseline behavior for the environment."],
  ["Investigation workflow", "Review detections, assets, sessions, artifacts, hunt playbooks, and PDF reports with an analyst-first operating model."]
];

const diagnostics = [
  ["App will not start", "Open the Windows Sensor Control Center, choose the installation folder, and use Open Logs to inspect the latest GUI log."],
  ["No packets visible", "Confirm Npcap, administrator rights, the selected adapter, and whether the traffic is actually visible from that machine."],
  ["Need full LAN coverage", "Move capture to a gateway, mirrored switch port, TAP, or deploy remote sensors. A laptop cannot see traffic that never reaches it."],
  ["GeoIP is offline", "Add a MaxMind GeoLite2 City MMDB path in the app settings. GeoIP is optional enrichment, not required for capture."]
];

const responsePaths = [
  ["Deploy", "Install the desktop sensor control center and validate packet visibility."],
  ["Tune", "Adjust profiles, enrichment, and detection volume for the environment."],
  ["Investigate", "Pivot through detections, assets, sessions, hunts, and reports."],
  ["Scale", "Extend visibility with gateway placement, SPAN/TAP, or distributed collectors."]
];

export default function SupportPage() {
  return (
    <main className="relative overflow-hidden">
      <section className="mx-auto grid max-w-7xl gap-10 px-6 py-24 lg:grid-cols-[.9fr_1.1fr] lg:items-end">
        <div>
          <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Support</p>
          <h1 className="mt-4 text-5xl font-semibold leading-[.96] tracking-[-0.065em] text-white md:text-7xl">Operate with confidence from first packet to final report.</h1>
          <p className="mt-6 text-xl leading-9 text-slate-300">Support is organized around the real deployment journey: install the GUI, confirm capture visibility, tune detections, investigate evidence, and expand coverage responsibly.</p>
        </div>
        <div className="depth-card rounded-[2rem] p-6">
          <p className="text-xs font-black uppercase tracking-[.2em] text-signal">Developed by</p>
          <a className="mt-3 inline-block text-3xl font-semibold tracking-[-.05em] text-white underline decoration-signal/60 underline-offset-4 transition hover:text-signal" href={PORTFOLIO_URL} target="_blank" rel="noreferrer">HeliSudani</a>
          <p className="mt-4 leading-7 text-slate-300">Ravynel Security is developed as a launch-ready enterprise NDR product surface for local sensor control, live network detection, investigation workflows, and executive reporting.</p>
        </div>
      </section>

      <section className="mx-auto grid max-w-7xl gap-5 px-6 md:grid-cols-2 xl:grid-cols-4">
        {supportTracks.map(([title, detail]) => (
          <article key={title} className="rounded-[2rem] border border-white/10 bg-white/[.04] p-6 transition hover:border-signal/35 hover:bg-signal/10">
            <h2 className="text-xl font-semibold tracking-[-.03em] text-white">{title}</h2>
            <p className="mt-3 leading-7 text-slate-300">{detail}</p>
          </article>
        ))}
      </section>

      <section className="mx-auto mt-14 grid max-w-7xl gap-6 px-6 lg:grid-cols-[1.05fr_.95fr]">
        <div className="rounded-[2rem] border border-white/10 bg-white/[.04] p-6">
          <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Troubleshooting</p>
          <h2 className="mt-3 text-3xl font-semibold tracking-[-.05em] text-white">Fast answers for common operator questions.</h2>
          <div className="mt-6 grid gap-3">
            {diagnostics.map(([title, detail]) => (
              <article key={title} className="rounded-2xl bg-black/20 p-4">
                <h3 className="font-semibold text-white">{title}</h3>
                <p className="mt-2 leading-7 text-slate-300">{detail}</p>
              </article>
            ))}
          </div>
        </div>
        <div className="mission-shell rounded-[2rem] border border-signal/25 p-6">
          <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Operator path</p>
          <h2 className="mt-3 text-3xl font-semibold tracking-[-.05em] text-white">Support follows the way teams actually deploy.</h2>
          <div className="mt-6 grid gap-3">
            {responsePaths.map(([title, detail]) => (
              <div key={title} className="rounded-2xl bg-black/25 p-4">
                <p className="text-xs font-black uppercase tracking-[.16em] text-signal">{title}</p>
                <p className="mt-2 leading-7 text-white">{detail}</p>
              </div>
            ))}
          </div>
          <div className="mt-5 rounded-2xl border border-white/10 bg-black/25 p-4">
            <p className="text-xs font-black uppercase tracking-[.16em] text-slate-500">Contact</p>
            <p className="mt-2 leading-7 text-white">helisudani0@gmail.com</p>
          </div>
        </div>
      </section>
    </main>
  );
}
