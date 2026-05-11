import "./globals.css";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Ravynel Security | Enterprise Network Defense",
  description: "Enterprise SOC platform for network discovery, distributed sensors, alert triage, and investigation reporting."
};

const PORTFOLIO_URL = "https://helisudani0.github.io/Heli_Sudani-Portfolio/";

const nav = [
  ["Platform", "/"],
  ["Documentation", "/docs"],
  ["Downloads", "/download"],
  ["Releases", "/releases"],
  ["Support", "/support"]
];

function Logo() {
  return (
    <span className="flex items-center gap-3">
      <svg className="h-11 w-11 drop-shadow-[0_16px_28px_rgba(84,216,255,0.18)]" viewBox="0 0 120 120" role="img" aria-label="Ravynel Security logo">
        <defs><linearGradient id="ravynel-site-g" x1="15" y1="12" x2="104" y2="108"><stop stopColor="#54D8FF"/><stop offset="1" stopColor="#FF8B61"/></linearGradient></defs>
        <rect width="120" height="120" rx="28" fill="#07111C" />
        <path d="M24 66c20-36 46-47 76-34-23 5-39 19-47 40 14-7 30-8 49-3-23 10-42 21-58 35-3-17-10-30-20-38Z" fill="url(#ravynel-site-g)" />
        <circle cx="72" cy="43" r="4.5" fill="#07111C" />
      </svg>
      <span className="leading-none">
        <span className="block text-[10px] font-black uppercase tracking-[0.22em] text-signal">Network Defense</span>
        <span className="mt-1 block text-xl font-semibold tracking-[-0.04em] text-white">Ravynel Security</span>
      </span>
    </span>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="sticky top-0 z-40 border-b border-white/10 bg-ink/85 backdrop-blur-xl">
          <div className="mx-auto flex max-w-7xl items-center justify-between gap-6 px-6 py-4">
            <Link href="/" className="font-semibold tracking-tight"><Logo /></Link>
            <nav className="hidden items-center gap-7 text-sm font-medium text-slate-300 md:flex">
              {nav.map(([label, href]) => <Link key={href} href={href} className="hover:text-white">{label}</Link>)}
            </nav>
            <Link href="/download" className="rounded-full bg-white px-4 py-2 text-sm font-semibold text-ink">Get installer</Link>
          </div>
        </header>
        {children}
        <footer className="border-t border-white/10 bg-black/20 px-6 py-10 text-sm text-slate-400">
          <div className="mx-auto grid max-w-7xl gap-6 md:grid-cols-[1fr_auto] md:items-end">
            <div>
              <p className="text-xs font-black uppercase tracking-[0.22em] text-signal">Ravynel Security</p>
              <p className="mt-2 max-w-2xl leading-6 text-slate-400">Enterprise network detection and response product surface, desktop sensor control center, and local analyst console.</p>
            </div>
            <div className="text-left md:text-right">
              <p className="font-semibold text-white">Developed by: <a className="underline decoration-signal/60 underline-offset-4 transition hover:text-signal" href={PORTFOLIO_URL} target="_blank" rel="noreferrer">HeliSudani</a></p>
              <p className="mt-2 text-slate-500">Network defense, detection engineering, and product experience.</p>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}

