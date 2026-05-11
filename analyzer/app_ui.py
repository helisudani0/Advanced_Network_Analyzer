from __future__ import annotations


def render_site_html() -> str:
    return render_launcher_html()


def render_launcher_html() -> str:
    return r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ravynel NDR Console</title>
  <style>
    :root{
      color-scheme:dark;
      --bg:#060B12;
      --panel:#0A121D;
      --panel-2:#0D1824;
      --panel-3:#101D2B;
      --line:#1B2A3B;
      --line-strong:#294158;
      --text:#F2F7FF;
      --muted:#9BAABC;
      --soft:#708397;
      --cyan:#4ED8FF;
      --teal:#34D6B6;
      --green:#59E29B;
      --amber:#F3C86A;
      --red:#FF6F86;
      --orange:#F59B72;
      --shadow:0 22px 70px rgba(0,0,0,.34);
      --radius:18px;
    }
    *{box-sizing:border-box}
    html{scroll-behavior:smooth}
    body{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 12% -8%,rgba(78,216,255,.12),transparent 30rem),
        radial-gradient(circle at 90% 0%,rgba(52,214,182,.07),transparent 28rem),
        linear-gradient(135deg,#060B12,#07121D 58%,#050910);
      color:var(--text);
      font-family:"Segoe UI Variable","Segoe UI",Aptos,Inter,Arial,sans-serif;
      font-size:14px;
      -webkit-font-smoothing:antialiased;
      text-rendering:geometricPrecision;
    }
    button,input,select,textarea{font:inherit}
    button{cursor:pointer}
    a{color:inherit;text-decoration:none}
    .app{display:grid;grid-template-columns:264px minmax(0,1fr);height:100vh;overflow:hidden}
    .side{
      border-right:1px solid var(--line);
      background:linear-gradient(180deg,rgba(5,10,16,.98),rgba(6,14,22,.96));
      padding:22px 18px;
      display:flex;
      flex-direction:column;
      gap:20px;
    }
    .brand{display:grid;grid-template-columns:46px 1fr;gap:12px;align-items:center}
    .logo{width:46px;height:46px;filter:drop-shadow(0 14px 26px rgba(78,216,255,.18))}
    .kicker{color:var(--cyan);font-size:10px;font-weight:800;letter-spacing:.18em;text-transform:uppercase}
    .brand b{display:block;margin-top:4px;font-size:20px;letter-spacing:-.025em}
    .nav-label{margin:4px 0 0;color:var(--soft);font-size:10px;font-weight:850;letter-spacing:.17em;text-transform:uppercase}
    .nav{display:grid;gap:5px}
    .nav button{
      display:flex;align-items:center;justify-content:space-between;width:100%;
      border:1px solid transparent;border-radius:13px;background:transparent;color:#A7B7C8;
      padding:11px 13px;text-align:left;font-weight:720;transition:.18s ease;
    }
    .nav button span{font-size:9px;color:var(--cyan);letter-spacing:.08em;text-transform:uppercase}
    .nav button.active,.nav button:hover{color:var(--text);background:rgba(78,216,255,.075);border-color:rgba(78,216,255,.22)}
    .side-note{margin-top:auto;border:1px solid rgba(78,216,255,.18);border-radius:16px;background:rgba(78,216,255,.055);padding:14px;color:#BFD0DD;font-size:13px;line-height:1.45}
    .main{min-width:0;height:100vh;display:grid;grid-template-rows:auto 1fr}
    .top{
      border-bottom:1px solid var(--line);
      background:rgba(6,12,19,.88);
      backdrop-filter:blur(18px);
      padding:18px 30px;
      display:flex;align-items:center;justify-content:space-between;gap:18px;
    }
    .title h1{margin:3px 0 0;font-size:30px;letter-spacing:-.045em;line-height:1.02}
    .title p{margin:7px 0 0;color:var(--muted);font-size:14px}
    .actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    .btn{
      border:1px solid var(--line-strong);border-radius:12px;background:rgba(16,29,43,.86);
      color:var(--text);padding:9px 14px;font-weight:750;letter-spacing:-.01em;transition:.16s ease;
    }
    .btn:hover:not(:disabled){transform:translateY(-1px);border-color:rgba(78,216,255,.42)}
    .btn.primary{border-color:rgba(78,216,255,.45);background:linear-gradient(135deg,rgba(78,216,255,.24),rgba(52,214,182,.13))}
    .btn.danger{color:#FFD8DE;border-color:rgba(255,111,134,.34);background:rgba(255,111,134,.09)}
    .btn:disabled{opacity:.45;cursor:not-allowed;transform:none}
    .status{display:flex;align-items:center;gap:9px;border:1px solid var(--line-strong);border-radius:999px;background:rgba(255,255,255,.035);padding:9px 13px;color:#C7D5E2;font-weight:750}
    .dot{width:8px;height:8px;border-radius:50%;background:#77889A}.dot.live{background:var(--green);box-shadow:0 0 0 6px rgba(89,226,155,.12)}
    .content{overflow:auto;padding:28px 30px 40px;max-width:1540px;width:100%;margin:0 auto}
    .view{display:none}.view.active{display:block}
    .grid{display:grid;gap:18px}.two{grid-template-columns:minmax(0,1fr) minmax(360px,.74fr)}.three{grid-template-columns:repeat(3,minmax(0,1fr))}.four{grid-template-columns:repeat(4,minmax(0,1fr))}
    .card{border:1px solid rgba(78,216,255,.13);border-radius:var(--radius);background:linear-gradient(180deg,rgba(16,29,43,.92),rgba(10,18,29,.94));box-shadow:var(--shadow)}
    .pad{padding:22px}
    .hero{display:grid;grid-template-columns:minmax(0,1.12fr) minmax(360px,.88fr);gap:18px}
    .hero-title{font-size:32px;letter-spacing:-.055em;line-height:1.08;margin:9px 0 12px;max-width:720px}
    .muted{color:var(--muted);line-height:1.55;font-size:15px}
    .metric{padding:16px;border-radius:15px;background:rgba(3,9,15,.44);border:1px solid rgba(148,163,184,.12)}
    .metric label,.label{display:block;color:#8EA3B7;font-size:10px;font-weight:850;letter-spacing:.15em;text-transform:uppercase}
    .metric b{display:block;margin-top:9px;font-size:27px;letter-spacing:-.04em;line-height:1.05}
    .metric small{display:block;margin-top:6px;color:var(--muted);line-height:1.35}
    .runtime{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.runtime .metric{min-height:118px}
    .head{display:flex;align-items:flex-end;justify-content:space-between;gap:14px;margin-bottom:14px}.head h2{margin:0;font-size:21px;letter-spacing:-.04em}.head p{margin:5px 0 0;color:var(--muted);line-height:1.4}
    .badge{display:inline-flex;align-items:center;border-radius:999px;padding:4px 9px;background:rgba(78,216,255,.11);color:#C7EFFF;font-size:10px;font-weight:850;text-transform:uppercase;letter-spacing:.055em;white-space:nowrap}.badge.medium{background:rgba(243,200,106,.15);color:#FFE0A2}.badge.high,.badge.critical{background:rgba(255,111,134,.16);color:#FFC7D0}.badge.active,.badge.ok{background:rgba(89,226,155,.14);color:#C8FFDD}.badge.optional{background:rgba(153,172,255,.15);color:#DCE3FF}
    .form{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.field label{display:block;margin-bottom:7px;color:#8EA3B7;font-size:10px;font-weight:850;letter-spacing:.13em;text-transform:uppercase}
    input,select,textarea{width:100%;border:1px solid var(--line);border-radius:12px;background:#050D16;color:var(--text);padding:10px 12px;outline:none}textarea{min-height:78px;resize:vertical}input:focus,select:focus,textarea:focus{border-color:rgba(78,216,255,.48);box-shadow:0 0 0 3px rgba(78,216,255,.08)}
    .toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.notice{min-height:21px;margin-top:11px;color:#C3D4E2}.notice.error{color:#FFC4CC}
    .table-wrap{overflow:auto;border:1px solid rgba(148,163,184,.12);border-radius:15px;max-height:560px}table{width:100%;border-collapse:collapse;table-layout:fixed;background:rgba(5,12,19,.22)}th{padding:12px;text-align:left;color:#91A6BA;font-size:10px;font-weight:850;letter-spacing:.14em;text-transform:uppercase;border-bottom:1px solid rgba(148,163,184,.14)}td{padding:13px 12px;border-bottom:1px solid rgba(148,163,184,.08);vertical-align:top;color:#E7F2FF;overflow-wrap:anywhere;line-height:1.35}tr:hover td{background:rgba(78,216,255,.035)}
    .empty{border:1px dashed rgba(148,163,184,.24);border-radius:15px;background:rgba(255,255,255,.025);padding:22px;text-align:center;color:var(--muted)}
    .bars{display:grid;gap:10px}.bar{display:grid;grid-template-columns:104px 1fr 54px;gap:10px;align-items:center;color:#C5D4E1}.track{height:9px;border-radius:99px;background:rgba(148,163,184,.14);overflow:hidden}.fill{height:100%;min-width:3px;border-radius:inherit;background:linear-gradient(90deg,var(--cyan),var(--orange))}
    .modules{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px}.module{border:1px solid rgba(148,163,184,.13);border-radius:16px;background:rgba(3,10,17,.34);padding:16px;min-height:142px}.module h3{margin:11px 0 6px;font-size:16px}.module p{margin:0;color:var(--muted);line-height:1.45}
    .timeline{display:grid;gap:9px;max-height:390px;overflow:auto}.event{display:grid;grid-template-columns:74px 86px 1fr;gap:9px;align-items:start;padding:11px;border:1px solid rgba(148,163,184,.11);border-radius:14px;background:rgba(3,10,17,.34)}.event time{color:#9EB0C2;font-size:12px}.event b{display:block;font-size:13px}.event small{display:block;margin-top:4px;color:var(--muted);line-height:1.35}
    .switches{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:14px}.check{display:flex;align-items:center;gap:9px;border:1px solid rgba(148,163,184,.13);border-radius:13px;padding:10px;color:#CBD9E6}.check input{width:auto}.split{display:grid;grid-template-columns:minmax(0,1fr) minmax(360px,.78fr);gap:18px}.subtabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:15px}.subtabs button{border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.04);color:#B8C8D8;padding:8px 12px;font-weight:750}.subtabs button.active{border-color:rgba(78,216,255,.34);color:#fff;background:rgba(78,216,255,.11)}
    @media(max-width:1200px){.hero,.two,.three,.split{grid-template-columns:1fr}.four,.modules,.form,.runtime,.switches{grid-template-columns:repeat(2,minmax(0,1fr))}.content{max-width:100%}}
    @media(max-width:820px){.app{grid-template-columns:1fr;overflow:auto;height:auto}.side{position:relative}.main{height:auto}.top{position:relative;flex-direction:column;align-items:flex-start}.content{overflow:visible;padding:20px}.four,.modules,.form,.runtime,.switches{grid-template-columns:1fr}.event{grid-template-columns:1fr}}

    /* Launch-grade console polish */
    body{background:radial-gradient(circle at 14% -12%,rgba(84,216,255,.18),transparent 28rem),radial-gradient(circle at 88% 0%,rgba(255,154,114,.10),transparent 28rem),linear-gradient(135deg,#040910,#07131d 54%,#050810);font-family:"Segoe UI Variable","Segoe UI",Aptos,ui-sans-serif,system-ui,sans-serif}
    body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.026) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.026) 1px,transparent 1px);background-size:64px 64px;mask-image:radial-gradient(circle at 52% 20%,black,transparent 78%)}
    .app{grid-template-columns:280px minmax(0,1fr)}
    .side{padding:26px 20px;background:linear-gradient(180deg,rgba(3,8,14,.985),rgba(5,13,21,.965));box-shadow:16px 0 60px rgba(0,0,0,.22)}
    .brand{grid-template-columns:50px 1fr}.logo{width:50px;height:50px}.brand b{font-size:20px;letter-spacing:-.035em}.nav{gap:7px}.nav button{border-radius:16px;padding:13px 14px;font-weight:760}.nav button.active,.nav button:hover{background:linear-gradient(135deg,rgba(84,216,255,.11),rgba(63,241,194,.035));border-color:rgba(84,216,255,.28);box-shadow:inset 0 1px 0 rgba(255,255,255,.045)}
    .side-note{border-radius:18px;background:rgba(84,216,255,.06);line-height:1.5}
    .top{padding:20px 36px;background:rgba(4,9,16,.84);backdrop-filter:blur(18px)}.title h1{font-size:34px;letter-spacing:-.055em}.title p{font-size:14px;color:#a8b8c8}
    .btn{border-color:rgba(139,168,194,.16);border-radius:14px;background:linear-gradient(180deg,rgba(255,255,255,.055),rgba(255,255,255,.025));font-weight:800;box-shadow:inset 0 1px 0 rgba(255,255,255,.04)}.btn:hover:not(:disabled){border-color:rgba(84,216,255,.44);background:rgba(84,216,255,.10)}.btn.primary{border-color:rgba(84,216,255,.48);background:linear-gradient(135deg,rgba(84,216,255,.28),rgba(63,241,194,.13))}.btn.danger{background:rgba(255,111,134,.085)}
    .status{border-color:rgba(139,168,194,.16);background:rgba(255,255,255,.04)}.dot.warn{background:var(--amber);box-shadow:0 0 0 6px rgba(243,200,106,.13)}
    .content{padding:30px 36px 44px;max-width:1580px}.card{position:relative;overflow:hidden;border-color:rgba(84,216,255,.14);border-radius:24px;background:linear-gradient(180deg,rgba(16,29,43,.92),rgba(8,17,27,.95));box-shadow:0 24px 80px rgba(0,0,0,.36),inset 0 1px 0 rgba(255,255,255,.04)}.card:before{content:"";position:absolute;inset:-40% auto auto -20%;width:45%;height:90%;background:radial-gradient(circle,rgba(84,216,255,.12),transparent 62%);pointer-events:none}.pad{padding:26px}.hero{gap:22px}.hero-title{font-size:38px;letter-spacing:-.065em;line-height:1.02;margin:12px 0 14px}.muted{font-size:15px;line-height:1.62}.metric{border-radius:18px;background:rgba(3,9,15,.46)}.metric label,.label,.field label{font-weight:900}.metric b{font-size:30px;letter-spacing:-.05em}.runtime{gap:14px}.runtime .metric{min-height:132px}.head h2{font-size:22px}.head p{color:#a8b8c8}.badge.warn{background:rgba(243,200,106,.15);color:#ffe2a2}
    input,select,textarea{border-color:rgba(139,168,194,.18);border-radius:14px;background:#050d16}.toolbar{margin-top:16px}.notice.ok{color:#cafede}.table-wrap{border-radius:18px}th{font-weight:900}td{line-height:1.38}.empty{border-radius:18px}.modules{gap:14px}.module{border-radius:18px;background:rgba(3,10,17,.38);transition:.18s ease}.module:hover{transform:translateY(-2px);border-color:rgba(84,216,255,.34);background:rgba(84,216,255,.065)}
    .hero-card{min-height:386px;isolation:isolate}.hero-card>*:not(.sensor-orbit){position:relative;z-index:2}.sensor-orbit{position:absolute;right:28px;top:26px;width:210px;height:210px;border-radius:50%;background:radial-gradient(circle at 50% 50%,rgba(84,216,255,.18),transparent 30%),repeating-conic-gradient(from 20deg,rgba(84,216,255,.18) 0 10deg,transparent 10deg 28deg);opacity:.62;filter:drop-shadow(0 0 34px rgba(84,216,255,.16));pointer-events:none}.sensor-orbit:before{content:"";position:absolute;inset:31px;border:1px solid rgba(84,216,255,.22);border-radius:50%;box-shadow:inset 0 0 28px rgba(84,216,255,.08)}.sensor-orbit:after{content:"";position:absolute;left:50%;top:50%;width:9px;height:9px;margin:-4px;border-radius:50%;background:#54d8ff;box-shadow:52px 8px 0 #ff9a72,-42px 34px 0 #3ff1c2,24px -48px 0 #9ab6ff}.hero-title{max-width:620px;font-size:36px;font-weight:780;letter-spacing:-.055em}.hero-card .muted{max-width:720px}.grid.four{max-width:760px}.runtime .metric{display:flex;flex-direction:column;justify-content:center}.runtime .metric b{font-size:28px}.notice{min-height:24px}.table-wrap::-webkit-scrollbar,.timeline::-webkit-scrollbar{height:10px;width:10px}.table-wrap::-webkit-scrollbar-thumb,.timeline::-webkit-scrollbar-thumb{background:rgba(148,163,184,.28);border-radius:999px}.table-wrap::-webkit-scrollbar-track,.timeline::-webkit-scrollbar-track{background:rgba(255,255,255,.035)}
    ::selection{background:rgba(78,216,255,.22);color:#f8fcff}input::selection,textarea::selection{background:rgba(78,216,255,.28);color:#fff}button,.badge,.kicker,.nav-label,.status,.side-note,.head h2,.head p,.metric label,.metric small,.field label,th{user-select:none}.content{scrollbar-gutter:stable}.table-wrap{max-height:none;overflow-x:auto;overflow-y:visible}.table-wrap.tall{max-height:620px;overflow:auto}.table-wrap table{min-width:840px;table-layout:auto}.table-wrap.detections table{min-width:1180px}.table-wrap.assets table{min-width:1080px}.table-wrap.sessions table{min-width:980px}.table-wrap.artifacts table{min-width:920px}.table-wrap.reports table{min-width:760px}.table-wrap.saved table{min-width:680px}td{overflow-wrap:normal;word-break:normal}.mono{font-family:"Cascadia Code","SFMono-Regular",Consolas,monospace;font-size:12px;letter-spacing:-.03em}.cell-main{display:block;color:#F4F8FF;font-weight:760}.cell-sub{display:block;margin-top:5px;color:#90A5B8;font-size:12px;line-height:1.35}.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}.nowrap{white-space:nowrap}.table-wrap.sessions td:first-child,.table-wrap.assets td:first-child,.table-wrap.detections td:nth-child(3),.table-wrap.detections td:nth-child(4){max-width:360px}.table-wrap.reports td:first-child{white-space:nowrap}.actions .btn,.toolbar .btn{white-space:nowrap}.field input,.field textarea{white-space:nowrap;text-overflow:ellipsis}.view{animation:fadeIn .18s ease}@keyframes fadeIn{from{opacity:.75;transform:translateY(4px)}to{opacity:1;transform:none}}
  </style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand"><svg class="logo" viewBox="0 0 120 120" aria-label="Ravynel logo"><defs><linearGradient id="g" x1="15" y1="12" x2="104" y2="108"><stop stop-color="#54D8FF"/><stop offset="1" stop-color="#FF8B61"/></linearGradient></defs><rect width="120" height="120" rx="28" fill="#07111C"/><path d="M24 66c20-36 46-47 76-34-23 5-39 19-47 40 14-7 30-8 49-3-23 10-42 21-58 35-3-17-10-30-20-38Z" fill="url(#g)"/><circle cx="72" cy="43" r="4.5" fill="#07111C"/></svg><div><div class="kicker">Network Defense</div><b>Ravynel NDR</b></div></div>
    <p class="nav-label">Workspace</p><nav class="nav" id="nav"><button data-view="overview" class="active">Overview <span>Live</span></button><button data-view="detections">Detections <span>Alerts</span></button><button data-view="coverage">Coverage <span>Modules</span></button><button data-view="assets">Assets <span>Inventory</span></button><button data-view="sessions">Sessions <span>Streams</span></button><button data-view="hunts">Hunts <span>Playbooks</span></button><button data-view="reports">Reports <span>PDF</span></button><button data-view="settings">Settings <span>Runtime</span></button></nav>
    <div class="side-note">This console shows observed telemetry only. Use gateway, SPAN/TAP, or distributed sensors for full LAN coverage.</div>
  </aside>
  <main class="main"><header class="top"><div class="title"><div class="kicker">Security Operations Console</div><h1 id="view-title">Overview</h1><p id="view-subtitle">Live network visibility and sensor control.</p></div><div class="actions"><button id="start-top" class="btn primary">Start capture</button><button id="all-top" class="btn">All adapters</button><button id="stop-top" class="btn danger">Stop</button><div class="status"><span id="status-dot" class="dot"></span><span id="status-text">Checking sensor</span></div></div></header><div class="content">
<section id="view-overview" class="view active">
  <div class="hero">
    <div class="card pad hero-card"><div class="sensor-orbit" aria-hidden="true"></div><div class="kicker">Live Sensor</div><div class="hero-title">Live sensor command center.</div><p class="muted">Start packet capture, review detections, inspect assets, and generate investigation-ready reports from one focused console.</p><div class="grid four" style="margin-top:16px"><div class="metric"><label>Packets</label><b id="packets">0</b><small>Inspected</small></div><div class="metric"><label>Detections</label><b id="alerts">0</b><small>Prioritized</small></div><div class="metric"><label>Assets</label><b id="hosts">0</b><small>Observed</small></div><div class="metric"><label>Sessions</label><b id="sessions">0</b><small>Tracked</small></div></div></div>
    <div class="card pad"><div class="runtime"><div class="metric"><label>Sensor</label><b id="sensor-state">Standby</b><small id="sensor-detail">Waiting for capture.</small></div><div class="metric"><label>Models</label><b id="model-state">Learning</b><small id="model-detail">Baseline and ML status.</small></div><div class="metric"><label>GeoIP</label><b id="geoip-state">Offline</b><small id="geoip-detail">Not configured.</small></div><div class="metric"><label>Intel</label><b id="intel-state">0</b><small id="intel-detail">Indicators loaded.</small></div></div></div>
  </div>
  <div class="grid two" style="margin-top:16px">
    <div class="card pad"><div class="head"><div><h2>Capture Plan</h2><p>Configure the local sensor before capture starts.</p></div><span id="capture-mode" class="badge">Standby</span></div><div class="form"><div class="field"><label>Interfaces</label><input id="interfaces" placeholder="blank, Ethernet, Wi-Fi, or all"></div><div class="field"><label>BPF Filter</label><input id="bpf" placeholder="tcp or udp"></div><div class="field"><label>Quick Filter</label><select id="quick-filter"><option value="all">All traffic</option><option value="http">HTTP/HTTPS</option><option value="dns">DNS only</option><option value="external">External traffic</option></select></div><div class="field"><label>Parser</label><select id="packet-parser"><option value="scapy">Scapy</option><option value="dpkt">dpkt</option><option value="pyshark">PyShark</option><option value="auto">Auto</option></select></div></div><div class="toolbar"><button id="save" class="btn">Save</button><button id="start" class="btn primary">Start capture</button><button id="all" class="btn">Monitor all adapters</button><button id="stop" class="btn danger">Stop</button><button id="report" class="btn">PDF report</button></div><div id="notice" class="notice"></div></div>
    <div class="card pad"><div class="head"><div><h2>Operational Snapshot</h2><p>Recent traffic, severity, and protocol shape.</p></div><button id="refresh" class="btn">Refresh</button></div><div id="traffic-chart" class="bars"></div><div id="severity-chart" class="bars" style="margin-top:14px"></div></div>
  </div>
</section>

<section id="view-detections" class="view"><div class="card pad"><div class="head"><div><h2>Detection Queue</h2><p>Prioritized alerts with entity, destination, score, and ATT&CK context.</p></div><span class="badge active">Live queue</span></div><div id="detections-table"></div></div><div class="grid two" style="margin-top:16px"><div class="card pad"><h2 style="margin-top:0">MITRE ATT&CK</h2><div id="mitre-chart" class="bars"></div></div><div class="card pad"><h2 style="margin-top:0">Alert Timeline</h2><div id="timeline" class="timeline"></div></div></div></section>

<section id="view-coverage" class="view"><div class="card pad"><div class="head"><div><h2>Coverage Matrix</h2><p>Implemented detection, enrichment, investigation, and deployment capabilities.</p></div><span class="badge active">Implemented</span></div><div class="subtabs" id="coverage-tabs"><button class="active" data-group="all">All</button><button data-group="detect">Detection</button><button data-group="intel">Intel</button><button data-group="investigate">Investigation</button><button data-group="platform">Platform</button></div><div id="feature-grid" class="modules"></div></div></section>

<section id="view-assets" class="view"><div class="card pad"><div class="head"><div><h2>Asset Inventory</h2><p>Observed hosts, risk posture, top destinations, and baseline readiness.</p></div><span id="asset-count" class="badge">0 assets</span></div><div id="assets-table"></div></div></section>

<section id="view-sessions" class="view"><div class="grid split"><div class="card pad"><div class="head"><div><h2>Sessions</h2><p>Recent conversations, bytes, requests, and stream evidence.</p></div></div><div id="sessions-table"></div></div><div class="card pad"><div class="head"><div><h2>Artifacts</h2><p>Files and payloads extracted from supported streams.</p></div></div><div id="artifacts-table"></div></div></div></section>

<section id="view-hunts" class="view"><div class="grid split"><div class="card pad"><div class="head"><div><h2>Threat Hunting</h2><p>Search alerts and save repeatable playbooks.</p></div></div><div class="form"><div class="field"><label>Search</label><input id="hunt-text" placeholder="classification, host, domain, technique"></div><div class="field"><label>Severity</label><select id="hunt-severity"><option value="">Any</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div><div class="field"><label>Host</label><input id="hunt-host" placeholder="source or host"></div><div class="field"><label>Technique</label><input id="hunt-technique" placeholder="T1046, T1071"></div></div><div class="toolbar"><button id="run-hunt" class="btn primary">Run hunt</button><input id="playbook-name" placeholder="Playbook name" style="max-width:260px"><button id="save-playbook" class="btn">Save playbook</button></div><div id="hunt-results" style="margin-top:14px"></div></div><div class="card pad"><div class="head"><div><h2>Saved Playbooks</h2><p>Reusable hunt queries stored in the database.</p></div></div><div id="saved-hunts"></div></div></div></section>

<section id="view-reports" class="view"><div class="grid split"><div class="card pad"><div class="head"><div><h2>Report Vault</h2><p>PDF investigation reports generated from observed telemetry.</p></div><button id="report-bottom" class="btn primary">Generate PDF</button></div><div id="reports-table"></div></div><div class="card pad"><div class="head"><div><h2>Operational Actions</h2><p>Replay evidence, benchmark ingest, and refresh intel feeds.</p></div></div><div class="form" style="grid-template-columns:1fr 140px"><div class="field"><label>PCAP Path</label><input id="pcap-path" placeholder="samples/capture.pcap"></div><div class="field"><label>Speed</label><input id="pcap-speed" type="number" step="0.25" value="0"></div></div><div class="toolbar"><button id="replay-pcap" class="btn">Replay PCAP</button><button id="timed-replay" class="btn">Timed replay</button><button id="benchmark" class="btn">Benchmark</button><button id="refresh-intel" class="btn">Refresh intel</button></div></div></div></section>

<section id="view-settings" class="view"><div class="card pad"><div class="head"><div><h2>Runtime Settings</h2><p>Configure enrichment, feeds, workers, parser, and model stack.</p></div></div><div class="form"><div class="field"><label>GeoIP DB Path</label><input id="geoip-db" placeholder="C:\path\GeoLite2-City.mmdb"></div><div class="field"><label>IOC Feed Paths / URLs</label><textarea id="ioc-sources" placeholder="feeds/threat_iocs.csv"></textarea></div><div class="field"><label>Workers</label><input id="workers" type="number" min="1" max="8" value="2"></div><div class="field"><label>Refresh Seconds</label><input id="refresh-seconds" type="number" min="2" max="60" value="5"></div></div><div class="switches"><label class="check"><input id="ml-enabled" type="checkbox" checked> Isolation Forest model</label><label class="check"><input id="sequence-enabled" type="checkbox" checked> Sequence model</label><label class="check"><input id="lstm-enabled" type="checkbox"> Optional LSTM model</label></div><div class="toolbar"><button id="save-settings-bottom" class="btn primary">Save settings</button><button id="profile-corporate" class="btn">Corporate profile</button><button id="profile-home" class="btn">Home lab profile</button><button id="profile-malware" class="btn">Malware profile</button></div></div></section>
</div></main></div>
<script>
const $=id=>document.getElementById(id),fmt=new Intl.NumberFormat();let state={},dash={},busy=false,coverageGroup='all';
const titles={overview:['Overview','Live network visibility and sensor control.'],detections:['Detections','Alert triage, MITRE mapping, and event timeline.'],coverage:['Coverage','Implemented NDR, enrichment, investigation, and platform capabilities.'],assets:['Assets','Observed hosts, risk posture, and baseline state.'],sessions:['Sessions','Conversation, stream, and artifact evidence.'],hunts:['Hunts','Search alerts and save repeatable playbooks.'],reports:['Reports','PDF reports, replay, benchmarks, and intel refresh.'],settings:['Settings','Runtime configuration and profiles.']};
const modules=[['detect','DNS tunneling','Long DNS queries, entropy, subdomain volume, high-frequency domains.'],['detect','Port scan detection','Horizontal scans, vertical scans, and half-open SYN bursts.'],['detect','Beaconing detection','Cadence and jitter analysis mapped to C2 behavior.'],['detect','Data exfil alerts','Outbound volume, suspicious uploads, DNS tunnel indicators, artifacts.'],['detect','Suspicious TLS','Legacy TLS, SNI metadata, mismatch, and self-signed certificate logic.'],['detect','HTTP anomalies','User-agent abuse, traversal, SQL injection, large POSTs, base64 blobs.'],['detect','IRC/P2P detection','IRC on unusual ports and BitTorrent/P2P fingerprints.'],['intel','Threat intel matching','Local feeds, IP/domain indicators, Tor lists, external feed URLs.'],['intel','Reputation scoring','IOC, GeoIP, port usage, traffic volume, severity, destination context.'],['intel','MITRE mapping','Detections tagged with ATT&CK tactic and technique.'],['investigate','TCP reconstruction','Sequence-aware stream tracking with previews and session evidence.'],['investigate','Artifact extraction','HTTP/FTP-oriented transferred-file and payload extraction metadata.'],['investigate','Baselines','Host protocol, destination, DNS, port, and behavior learning.'],['investigate','Threat hunting','Search alerts and save repeatable playbooks.'],['platform','Multi-interface capture','Default, selected interfaces, or all local adapters.'],['platform','BPF filtering','Capture filters with quick-filter presets.'],['platform','SQLite/PostgreSQL','SQLite default, PostgreSQL URLs, and SQLAlchemy storage.'],['platform','Profiles','Corporate network, home lab, and malware-analysis rulesets.'],['platform','ML anomaly detection','Isolation Forest, sequence model, and optional LSTM.'],['platform','Deep protocols','SMB, RDP, LDAP, Kerberos, FTP, DNS, HTTP, TLS, IRC, P2P.'],['platform','Passive OS fingerprinting','TTL, window, and flag hints for asset inventory.'],['platform','Integration APIs','REST endpoints, remote raw ingest, reports, sensors, saved hunts.']];
function arr(v){return Array.isArray(v)?v:[]}function esc(v){return String(v??'-').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}function short(v,n=64){const s=String(v??'-');return s.length>n?s.slice(0,n-1)+'...':s}function sev(v){const s=String(v||'LOW').toLowerCase();return `<span class="badge ${s}">${s.toUpperCase()}</span>`}function empty(m){return `<div class="empty">${esc(m)}</div>`}function table(h,d,r,m,cls=''){const rows=arr(d);if(!rows.length)return empty(m);return `<div class="table-wrap ${cls}"><table><thead><tr>${h.map(x=>`<th>${esc(x)}</th>`).join('')}</tr></thead><tbody>${rows.map(r).join('')}</tbody></table></div>`}function notice(m,e=false){$('notice').textContent=m||'';$('notice').className='notice '+(e?'error':'ok')}async function api(p,o={}){const timeout=o.timeout||12000,options={...o};delete options.timeout;const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);try{const r=await fetch(p,{cache:'no-store',headers:{'Content-Type':'application/json'},...options,signal:controller.signal});if(!r.ok){let d=await r.text();try{d=JSON.parse(d).detail||d}catch(_){}throw new Error(d||r.statusText)}return r.json()}catch(err){if(err&&err.name==='AbortError')throw new Error('The analyzer did not respond in time. Restart capture or check the launcher logs.');throw err}finally{clearTimeout(timer)}}function value(x,n){for(const k of n){if(x&&x[k]!==undefined&&x[k]!==null)return x[k]}return 0}function label(x,n){for(const k of n){if(x&&x[k]!==undefined&&x[k]!==null&&x[k]!=='')return x[k]}return'Unknown'}function chip(v,c='optional'){return `<span class="badge ${c}">${esc(v||'-')}</span>`}function mainSub(main,sub='',cls=''){return `<span class="cell-main ${cls}">${esc(main||'-')}</span>${sub?`<span class="cell-sub ${cls}">${esc(sub)}</span>`:''}`}function flow(v){const raw=String(v||'-'),parts=raw.split('-');if(parts.length>=3){const proto=parts.pop(),dst=parts.pop(),src=parts.join('-');return `<span class="cell-main mono truncate" title="${esc(raw)}">${esc(short(src,42))}</span><span class="cell-sub mono truncate" title="${esc(raw)}">${esc(short(dst,42))} -> ${esc(proto)}</span>`}return `<span class="cell-main mono truncate" title="${esc(raw)}">${esc(short(raw,70))}</span>`}function chart(data,labels,values,limit=5){const rows=arr(data).slice(0,limit).filter(x=>Number(value(x,values))>0);if(!rows.length)return empty('No chart data yet.');const max=Math.max(...rows.map(x=>Number(value(x,values))||0),1);return rows.map(x=>{const v=Number(value(x,values))||0,p=Math.max(4,Math.round(v/max*100));return `<div class="bar"><span>${esc(short(label(x,labels),20))}</span><div class="track"><div class="fill" style="width:${p}%"></div></div><b>${fmt.format(v)}</b></div>`}).join('')}function t(v){const n=Number(v);return Number.isFinite(n)&&n>0?new Date(n*1000).toLocaleTimeString():String(v||'-')}
function setView(name){document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));$(`view-${name}`).classList.add('active');document.querySelectorAll('.nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===name));$('view-title').textContent=titles[name][0];$('view-subtitle').textContent=titles[name][1];location.hash=name}
function renderModules(){const rows=modules.filter(m=>coverageGroup==='all'||m[0]===coverageGroup);$('feature-grid').innerHTML=rows.map(([g,n,d])=>`<article class="module"><span class="badge ${g==='platform'?'optional':'active'}">${esc(g)}</span><h3>${esc(n)}</h3><p>${esc(d)}</p></article>`).join('')}
function renderTimeline(rows){rows=arr(rows).slice(0,10);$('timeline').innerHTML=rows.length?rows.map(x=>`<div class="event"><time>${esc(t(x.timestamp||x.created_at))}</time>${sev(x.severity)}<div><b>${esc(short(x.title||x.classification||'Detection'))}</b><small>${esc(short(x.host||x.source||''))} -> ${esc(short(x.destination||''))}</small></div></div>`).join(''):empty('No timeline events yet.')}
function renderReports(rows){$('reports-table').innerHTML=table(['Report','Created','Open'],rows,x=>{const n=x.name||x.file_name||'report.pdf';return `<tr><td>${mainSub(n,'','mono truncate')}</td><td class="nowrap">${esc(x.created||x.created_at||'-')}</td><td><a class="badge active" href="/reports/file/${encodeURIComponent(n)}" target="_blank">Open PDF</a></td></tr>`},'No reports generated yet.','reports tall')}
function renderSaved(rows){$('saved-hunts').innerHTML=table(['Name','Dataset','Updated'],rows,x=>`<tr><td>${mainSub(x.name,'','truncate')}</td><td>${chip(x.dataset)}</td><td class="nowrap">${esc(x.updated_at||x.created_at||'-')}</td></tr>`,'No saved playbooks yet.','saved')}
function render(){
  const s=state.summary||{},set=state.settings||{},models=state.model_status||dash.model_status||{};
  const captureError=String(state.capture_error||dash.capture_error||'');
  const active=!!state.capture_active||!!dash.live_capture_active,geo=s.geoip_status||'GeoIP disabled';
  $('packets').textContent=fmt.format(s.packets_processed||0);$('alerts').textContent=fmt.format(s.alerts_generated||0);$('hosts').textContent=fmt.format(s.tracked_hosts||0);$('sessions').textContent=fmt.format(s.tracked_sessions||0);
  $('status-dot').className='dot '+(active?'live':captureError?'warn':'');$('status-text').textContent=active?'Capture running':captureError?'Capture needs attention':'Capture standby';$('capture-mode').textContent=active?'Online':captureError?'Attention':'Standby';$('capture-mode').className='badge '+(active?'active':captureError?'warn':'');
  $('sensor-state').textContent=active?'Online':captureError?'Attention':'Standby';$('sensor-detail').textContent=active?'Packets are being processed.':captureError||'Capture is stopped.';
  $('model-state').textContent=(models.lstm_sequence_model&&!String(models.lstm_sequence_model).startsWith('Disabled'))?'Advanced':'Learning';$('model-detail').textContent=[models.isolation_forest,models.sequence_model,models.lstm_sequence_model].filter(Boolean).join(' | ')||'Model status unavailable.';
  $('geoip-state').textContent=String(geo).toLowerCase().includes('enabled')?'Enabled':'Offline';$('geoip-detail').textContent=geo;$('intel-state').textContent=fmt.format(s.ioc_count||0);$('intel-detail').textContent='Indicators loaded.';
  ['start','start-top','all','all-top'].forEach(id=>$(id).disabled=active||busy);['stop','stop-top'].forEach(id=>$(id).disabled=!active||busy);
  if(captureError&&!active&&!busy&&!$('notice').textContent){notice(captureError,true)}
  if(!$('interfaces').dataset.loaded){$('interfaces').value=arr(set.interfaces).join(', ');$('bpf').value=set.bpf_filter||'';$('quick-filter').value=set.quick_filter||'all';$('packet-parser').value=set.packet_parser||'scapy';$('geoip-db').value=set.geoip_db||'';$('ioc-sources').value=arr(set.ioc_sources).join('\n');$('workers').value=set.worker_count||2;$('refresh-seconds').value=set.dashboard_refresh_seconds||5;$('ml-enabled').checked=set.ml_enabled!==false;$('sequence-enabled').checked=set.sequence_model_enabled!==false;$('lstm-enabled').checked=!!set.lstm_enabled;$('interfaces').dataset.loaded='1'}
  const alerts=arr(state.recent_alerts).length?arr(state.recent_alerts):arr(dash.alerts);
  $('detections-table').innerHTML=table(['Severity','Finding','Host','Destination','ATT&CK','Score'],alerts.slice(0,18),x=>`<tr><td>${sev(x.severity)}</td><td>${mainSub(short(x.title||x.classification,58),x.classification&&x.classification!==x.title?short(x.classification,58):'')}</td><td>${mainSub(short(x.host,44),'','mono truncate')}</td><td>${mainSub(short(x.destination,54),'','mono truncate')}</td><td>${mainSub(x.mitre_tactic||'-',x.mitre_technique||'')}</td><td class="nowrap">${esc(x.score||0)}</td></tr>`,'No detections yet. Normal traffic can create packets, sessions, and assets without triggering alerts.','detections tall');
  const assets=arr(dash.asset_inventory).length?arr(dash.asset_inventory):arr(dash.hosts);
  $('asset-count').textContent=`${fmt.format(assets.length)} assets`;$('assets-table').innerHTML=table(['Host','Role','Packets','Alerts','Risk','Top destination','Baseline'],assets.slice(0,30),x=>`<tr><td>${mainSub(short(x.host||x.ip,52),'','mono truncate')}</td><td>${esc(x.role||x.os_guess||'Observed host')}</td><td class="nowrap">${fmt.format(x.packets||x.packet_count||0)}</td><td class="nowrap">${fmt.format(x.alert_count||0)}</td><td>${sev(x.severity||(x.max_score>=20?'HIGH':'LOW'))}</td><td>${mainSub(short(arr(x.top_destinations)[0]?.destination||x.top_destination||'-',50),'','mono truncate')}</td><td>${x.baseline_ready?'<span class="badge active">Ready</span>':'<span class="badge optional">Learning</span>'}</td></tr>`,'No assets observed yet.','assets tall');
  $('sessions-table').innerHTML=table(['Session','Protocol','Bytes','Requests','Artifacts'],arr(dash.sessions).slice(0,20),x=>`<tr><td>${flow(x.session_id||x.id)}</td><td>${chip(`${x.transport||''}:${x.dst_port||''}`)}</td><td class="nowrap">${fmt.format(x.total_bytes||x.bytes||0)}</td><td class="nowrap">${fmt.format(x.http_requests||x.requests||0)}</td><td class="nowrap">${fmt.format(arr(x.artifacts).length||x.artifact_count||0)}</td></tr>`,'No sessions observed yet.','sessions tall');
  $('artifacts-table').innerHTML=table(['Artifact','Type','Status','Session'],arr(dash.artifacts).slice(0,20),x=>`<tr><td>${mainSub(short(x.file_name||x.name||x.source_url||'artifact',46),'','truncate')}</td><td>${esc(x.content_type||x.type||'-')}</td><td>${chip(x.status||'-','active')}</td><td>${flow(x.session_id||x.session||'-')}</td></tr>`,'No artifacts extracted yet.','artifacts tall');
  $('traffic-chart').innerHTML=chart(dash.traffic_series,['label','bucket','time'],['count','events','value']);$('severity-chart').innerHTML=chart(dash.severity_counts,['severity','label'],['count','value']);$('mitre-chart').innerHTML=chart(dash.mitre_heatmap,['technique','mitre_technique','tactic'],['count','value'],7);
  renderTimeline(arr(dash.timeline).length?dash.timeline:alerts);renderReports(arr(state.reports));renderSaved(arr(state.saved_hunts).length?state.saved_hunts:arr(dash.saved_hunts));renderModules();
}
async function load(){const [a,d]=await Promise.all([api('/app-data',{timeout:6000}),api('/dashboard-data',{timeout:6000})]);state=a||{};dash=d||{};render()}
async function action(label,fn,opts={}){if(busy)return;busy=true;notice(label);render();try{const r=await fn();await load();if(opts.expectCapture&&!state.capture_active){notice(state.capture_error||'Capture did not remain active. Check Npcap, administrator permissions, adapter name, and BPF filter.',true)}else{notice(r?.message||r?.status||'Action complete.')}}catch(e){notice(e.message,true)}finally{busy=false;render()}}
function payload(o={}){return{interfaces:$('interfaces').value,bpf_filter:$('bpf').value,quick_filter:$('quick-filter').value,packet_parser:$('packet-parser').value,geoip_db:$('geoip-db').value,ioc_sources:$('ioc-sources').value,worker_count:Number($('workers').value||2),dashboard_refresh_seconds:Number($('refresh-seconds').value||5),ml_enabled:$('ml-enabled').checked,sequence_model_enabled:$('sequence-enabled').checked,lstm_enabled:$('lstm-enabled').checked,...o}}
async function saveSettings(o={}){return api('/app/settings',{method:'POST',body:JSON.stringify(payload(o)),timeout:7000})}
async function start(){await saveSettings();return api('/capture/start',{method:'POST',timeout:7000})}
async function all(){ $('interfaces').value='all';await saveSettings({interfaces:'all'});return api('/capture/start',{method:'POST',timeout:7000})}
async function runHunt(){const p=new URLSearchParams();if($('hunt-text').value)p.set('text_query',$('hunt-text').value);if($('hunt-severity').value)p.set('severity',$('hunt-severity').value);if($('hunt-host').value)p.set('host',$('hunt-host').value);if($('hunt-technique').value)p.set('technique',$('hunt-technique').value);p.set('limit','50');const r=await api('/alerts/search?'+p);const rows=arr(r.alerts);$('hunt-results').innerHTML=table(['Severity','Finding','Host','Technique'],rows,x=>`<tr><td>${sev(x.severity)}</td><td>${mainSub(short(x.title||x.classification,58),x.classification&&x.classification!==x.title?short(x.classification,58):'')}</td><td>${mainSub(short(x.host,44),'','mono truncate')}</td><td>${chip(x.mitre_technique||'-')}</td></tr>`,'No matching alerts found.','detections tall');return{status:`${rows.length} hunt results`}}
async function savePlaybook(){const name=$('playbook-name').value.trim();if(!name)throw new Error('Enter a playbook name first.');return api('/hunt/saved',{method:'POST',body:JSON.stringify({name,dataset:'alerts',notes:'Saved from Ravynel NDR console.',query:{text_query:$('hunt-text').value,severity:$('hunt-severity').value,host:$('hunt-host').value,technique:$('hunt-technique').value}})})}
function bind(id,fn,opts={}){$(id).addEventListener('click',()=>action('Working...',fn,opts))}
['start','start-top'].forEach(id=>bind(id,start,{expectCapture:true}));['all','all-top'].forEach(id=>bind(id,all,{expectCapture:true}));['stop','stop-top'].forEach(id=>bind(id,()=>api('/capture/stop',{method:'POST'})));
bind('save',()=>saveSettings());bind('save-settings-bottom',()=>saveSettings());bind('report',()=>api('/reports/generate',{method:'POST'}));bind('report-bottom',()=>api('/reports/generate',{method:'POST'}));bind('refresh',()=>load().then(()=>({status:'Console refreshed.'})));bind('refresh-intel',()=>api('/intel/refresh',{method:'POST'}));bind('benchmark',()=>api('/benchmark/ingest?sample_count=10000'));bind('run-hunt',runHunt);bind('save-playbook',async()=>{const r=await savePlaybook();await load();return r});bind('profile-corporate',()=>api('/app/profile/corporate_network',{method:'POST'}));bind('profile-home',()=>api('/app/profile/home_lab',{method:'POST'}));bind('profile-malware',()=>api('/app/profile/malware_analysis',{method:'POST'}));bind('replay-pcap',()=>api('/pcap/replay',{method:'POST',body:JSON.stringify({pcap_path:$('pcap-path').value,playback_speed:Number($('pcap-speed').value||0)})}));bind('timed-replay',()=>api('/pcap/replay',{method:'POST',body:JSON.stringify({pcap_path:$('pcap-path').value,playback_speed:1})}));
document.querySelectorAll('.nav button').forEach(b=>b.addEventListener('click',()=>setView(b.dataset.view)));document.querySelectorAll('#coverage-tabs button').forEach(b=>b.addEventListener('click',()=>{coverageGroup=b.dataset.group;document.querySelectorAll('#coverage-tabs button').forEach(x=>x.classList.toggle('active',x===b));renderModules()}));
const initial=(location.hash||'#overview').slice(1);if(titles[initial])setView(initial);renderModules();load().catch(e=>notice('Unable to load console: '+e.message,true));setInterval(()=>load().catch(()=>{}),5000);
</script>
</body>
</html>"""




