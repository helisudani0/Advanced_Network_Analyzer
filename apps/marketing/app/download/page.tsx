const releaseBaseUrl =
  process.env.NEXT_PUBLIC_DOWNLOAD_BASE_URL ||
  "https://github.com/helisudani0/Ravynel-Security/releases/latest/download";

const assetUrl = (file: string) => `${releaseBaseUrl.replace(/\/$/, "")}/${file}`;

const packages = [
  {
    name: "Windows Sensor Control Center",
    file: "Ravynel-Windows-Launcher.zip",
    detail: "Recommended. Includes the desktop launcher, analyzer engine, profiles, feeds, and setup notes. Extract the package and open Ravynel-Launch.pyw to start from the GUI.",
    href: assetUrl("Ravynel-Windows-Launcher.zip"),
    primary: true
  },
  {
    name: "Linux Sensor Bootstrap",
    file: "ravynel-sensor-linux-install.sh",
    detail: "Headless sensor bootstrap for Linux hosts, gateway collectors, mirrored ports, and distributed network monitoring.",
    href: assetUrl("ravynel-sensor-linux-install.sh")
  },
  {
    name: "Kubernetes Control Plane Manifest",
    file: "ravynel-kubernetes-control-plane.yaml",
    detail: "Optional deployment manifest for teams moving from local analysis into centralized services and distributed sensors.",
    href: assetUrl("ravynel-kubernetes-control-plane.yaml")
  },
  {
    name: "Release Checksums",
    file: "checksums.txt",
    detail: "SHA-256 checksums for release validation before installation or internal distribution.",
    href: assetUrl("checksums.txt")
  }
];

const steps = [
  ["1", "Download", "Get the Windows Sensor Control Center package from the latest GitHub Release asset."],
  ["2", "Install prerequisites", "Install Python 3.12+ and Npcap. The package includes a first-run README with the exact setup path."],
  ["3", "Open the GUI", "Double-click Ravynel-Launch.pyw or Ravynel-Start.cmd. A small desktop control panel opens and stays visible."],
  ["4", "Start sensor", "The GUI detects the laptop LAN IP, starts Ravynel on that address, and shows the console URL."],
  ["5", "Operate", "Use the app console for capture, detections, assets, sessions, hunts, reports, and runtime settings."]
];

const requirements = [
  "Windows 10/11 with Python 3.12+ available as python, py, or pythonw.",
  "Npcap is required for live packet capture on Windows. Install it before first capture.",
  "Run the launcher as Administrator if Windows blocks packet-capture permissions.",
  "For full LAN visibility, deploy at a gateway, mirrored switch port, TAP, or distributed sensor.",
  "Unsigned scripts can trigger SmartScreen in some environments. Verify checksums and code-sign production builds before enterprise rollout."
];

export default function DownloadPage() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-20">
      <div className="grid gap-10 lg:grid-cols-[.86fr_1.14fr] lg:items-center">
        <div>
          <p className="text-sm font-black uppercase tracking-[0.25em] text-signal">Downloads</p>
          <h1 className="mt-4 text-5xl font-semibold leading-[.96] tracking-[-0.065em] text-white md:text-7xl">Install the sensor. Open the control GUI. Start capture.</h1>
          <p className="mt-6 max-w-3xl text-xl leading-9 text-slate-300">Ravynel is distributed as an operations package. The public site hosts product information; the downloadable release contains the launcher and analyzer components users need to run locally.</p>
        </div>
        <section className="glass rounded-[2.2rem] p-6">
          <h2 className="text-2xl font-semibold text-white">Recommended Windows flow</h2>
          <div className="mt-5 grid gap-3">
            {steps.map(([number, title, detail]) => (
              <article key={title} className="rounded-2xl border border-white/10 bg-white/[.04] p-4">
                <div className="flex items-center gap-3"><span className="grid h-8 w-8 place-items-center rounded-full bg-signal/15 text-xs font-black text-signal">{number}</span><h3 className="font-semibold text-white">{title}</h3></div>
                <p className="mt-2 leading-6 text-slate-300">{detail}</p>
              </article>
            ))}
          </div>
        </section>
      </div>

      <section className="mt-14 grid gap-5">
        {packages.map((item) => (
          <div key={item.file} className={`flex flex-wrap items-center justify-between gap-5 rounded-[2rem] border p-6 ${item.primary ? "border-signal/40 bg-signal/10" : "border-white/10 bg-white/[.04]"}`}>
            <div className="max-w-3xl">
              <p className="text-xs font-black uppercase tracking-[.2em] text-signal">{item.file}</p>
              <h2 className="mt-2 text-2xl font-semibold tracking-[-.04em] text-white">{item.name}</h2>
              <p className="mt-2 leading-7 text-slate-300">{item.detail}</p>
            </div>
            <a href={item.href} className="rounded-full bg-white px-6 py-3 font-bold text-ink">Download</a>
          </div>
        ))}
      </section>

      <section className="mt-14 rounded-[2rem] border border-white/10 bg-white/[.04] p-6">
        <h2 className="text-2xl font-semibold text-white">Capture requirements</h2>
        <div className="mt-5 grid gap-3 md:grid-cols-2">
          {requirements.map((item) => <p key={item} className="rounded-2xl bg-black/20 p-4 leading-7 text-slate-300">{item}</p>)}
        </div>
      </section>
    </main>
  );
}
