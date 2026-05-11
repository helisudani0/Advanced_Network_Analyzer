import os
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path
from tkinter import Menu, PhotoImage, StringVar, Tk, filedialog, messagebox
from tkinter import ttk

APP_NAME = "Ravynel Security"
APP_TITLE = "Ravynel Network Sensor"
LOGO_PNG_BASE64 = "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"


def candidate_roots() -> list[Path]:
    here = Path(__file__).resolve().parent
    home = Path.home()
    return [
        here,
        here.parent,
        Path.cwd(),
        home / "Desktop" / "Projects" / "Ravynel-Security",
        home / "Desktop" / "Ravynel-Security",
        home / "Downloads" / "Ravynel-Security",
    ]


def find_root() -> Path | None:
    for candidate in candidate_roots():
        if (candidate / "app.py").exists():
            return candidate.resolve()
    return None


def detect_lan_ip() -> str:
    probes = [("8.8.8.8", 80), ("1.1.1.1", 80), ("192.168.1.1", 80)]
    for host, port in probes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((host, port))
            ip = sock.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except OSError:
            pass
        finally:
            sock.close()
    try:
        host = socket.gethostname()
        for _, _, ips in socket.gethostbyname_ex(host):
            for ip in ips:
                if ip and not ip.startswith("127."):
                    return ip
    except OSError:
        pass
    return "127.0.0.1"


def free_port(start: int = 8080) -> int:
    for port in range(start, start + 120):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free local port found for Ravynel.")


def url_ready(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=1.0) as response:
            return response.status == 200
    except Exception:
        return False


def log_reports_ready(path: Path | None) -> bool:
    if not path or not path.exists():
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")[-4000:]
    except OSError:
        return False
    return "Live app:" in text or "Live packet capture is running" in text or "Launcher opened" in text


def wait_ready(urls: list[str], process: subprocess.Popen, out_log: Path | None, timeout: float = 26.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        if any(url_ready(url) for url in urls):
            return True
        if log_reports_ready(out_log):
            return True
        time.sleep(0.35)
    return process.poll() is None and log_reports_ready(out_log)


class RavynelControlCenter:
    def __init__(self) -> None:
        self.root_path = find_root()
        self.process: subprocess.Popen | None = None
        self.port: int | None = None
        self.out_log: Path | None = None
        self.err_log: Path | None = None
        self.lan_ip = detect_lan_ip()
        self.after_id: str | None = None

        self.window = Tk()
        self.window.title(APP_TITLE)
        self.window.geometry("700x450")
        self.window.minsize(680, 430)
        self.window.configure(bg="#f4f7fa")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)

        self.status = StringVar(value="Stopped")
        self.network_ip = StringVar(value=self.lan_ip)
        self.console_url = StringVar(value="Not running")
        self.install_path = StringVar(value=str(self.root_path or "Select installation folder"))
        self.log_path = StringVar(value="Logs will appear after start")
        self.message = StringVar(value="Ravynel is ready to start. The launcher detects this laptop's network address automatically.")

        self.configure_styles()
        self.build_menu()
        self.build_ui()
        self.refresh_status(schedule=True)

    def configure_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Root.TFrame", background="#f4f7fa")
        style.configure("Panel.TLabelframe", background="#f4f7fa", bordercolor="#bfc7d1", relief="solid")
        style.configure("Panel.TLabelframe.Label", background="#f4f7fa", foreground="#152234", font=("Segoe UI", 10, "bold"))
        style.configure("TLabel", background="#f4f7fa", foreground="#17202a", font=("Segoe UI", 9))
        style.configure("Value.TLabel", background="#f4f7fa", foreground="#0f1720", font=("Segoe UI", 10))
        style.configure("StatusRunning.TLabel", background="#f4f7fa", foreground="#087a43", font=("Segoe UI", 11, "bold"))
        style.configure("StatusStopped.TLabel", background="#f4f7fa", foreground="#9a3412", font=("Segoe UI", 11, "bold"))
        style.configure("StatusStarting.TLabel", background="#f4f7fa", foreground="#0f7594", font=("Segoe UI", 11, "bold"))
        style.configure("Primary.TButton", font=("Segoe UI", 9, "bold"), padding=(14, 6))
        style.configure("TButton", font=("Segoe UI", 9), padding=(12, 6))

    def build_menu(self) -> None:
        menu = Menu(self.window)
        manage = Menu(menu, tearoff=False)
        manage.add_command(label="Start Sensor", command=self.start)
        manage.add_command(label="Stop Sensor", command=self.stop)
        manage.add_separator()
        manage.add_command(label="Choose Installation Folder", command=self.choose_folder)
        manage.add_command(label="Exit", command=self.on_close)
        view = Menu(menu, tearoff=False)
        view.add_command(label="Open Console", command=self.open_console)
        view.add_command(label="Open Logs", command=self.open_logs)
        view.add_command(label="Refresh", command=lambda: self.refresh_status())
        help_menu = Menu(menu, tearoff=False)
        help_menu.add_command(label="About Ravynel", command=self.about)
        menu.add_cascade(label="Manage", menu=manage)
        menu.add_cascade(label="View", menu=view)
        menu.add_cascade(label="Help", menu=help_menu)
        self.window.config(menu=menu)

    def build_ui(self) -> None:
        root = ttk.Frame(self.window, style="Root.TFrame", padding=18)
        root.pack(fill="both", expand=True)

        header = ttk.Frame(root, style="Root.TFrame")
        header.pack(fill="x")
        self.draw_logo(header)
        title = ttk.Frame(header, style="Root.TFrame")
        title.pack(side="left", padx=14)
        ttk.Label(title, text="Ravynel NDR", font=("Segoe UI", 15, "bold"), background="#f4f7fa").pack(anchor="w")
        ttk.Label(title, text="Local network sensor control", foreground="#596675", background="#f4f7fa").pack(anchor="w")

        sensor = ttk.Labelframe(root, text="Sensor", style="Panel.TLabelframe", padding=14)
        sensor.pack(fill="x", pady=(18, 10))
        self.add_row(sensor, "Status", self.status, status=True)
        self.add_row(sensor, "Detected laptop IP", self.network_ip)
        self.add_row(sensor, "Console URL", self.console_url)
        self.add_row(sensor, "Installation folder", self.install_path)
        self.add_row(sensor, "Latest log", self.log_path)

        controls = ttk.Frame(root, style="Root.TFrame")
        controls.pack(fill="x", pady=8)
        self.start_button = ttk.Button(controls, text="Start", command=self.start, style="Primary.TButton")
        self.start_button.pack(side="left", padx=(0, 8))
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop)
        self.stop_button.pack(side="left", padx=(0, 8))
        self.open_button = ttk.Button(controls, text="Open Console", command=self.open_console)
        self.open_button.pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Choose Folder", command=self.choose_folder).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Refresh", command=lambda: self.refresh_status()).pack(side="left")

        note = ttk.Labelframe(root, text="Network visibility", style="Panel.TLabelframe", padding=12)
        note.pack(fill="both", expand=True, pady=(8, 0))
        ttk.Label(note, textvariable=self.message, wraplength=620, justify="left", foreground="#334155", background="#f4f7fa", font=("Segoe UI", 9)).pack(anchor="w", fill="x")

    def draw_logo(self, parent) -> None:
        try:
            self.logo_source = PhotoImage(data=LOGO_PNG_BASE64)
            self.logo_image = self.logo_source.subsample(2, 2)
            ttk.Label(parent, image=self.logo_image, background="#f4f7fa").pack(side="left")
        except Exception:
            ttk.Label(parent, text="R", font=("Segoe UI", 20, "bold"), foreground="#0f7594", background="#e0f7ff").pack(side="left", ipadx=14, ipady=8)

    def add_row(self, parent, label: str, variable: StringVar, status: bool = False) -> None:
        row = ttk.Frame(parent, style="Root.TFrame")
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=f"{label}:", width=22).pack(side="left")
        style = self.status_style() if status else "Value.TLabel"
        value = ttk.Label(row, textvariable=variable, style=style)
        value.pack(side="left", fill="x", expand=True)
        if status:
            self.status_label = value

    def status_style(self) -> str:
        value = self.status.get()
        if value == "Running":
            return "StatusRunning.TLabel"
        if value == "Starting":
            return "StatusStarting.TLabel"
        return "StatusStopped.TLabel"

    def set_message(self, value: str) -> None:
        self.message.set(value)

    def choose_folder(self) -> None:
        selected = filedialog.askdirectory(title="Select Ravynel-Security installation folder")
        if not selected:
            return
        path = Path(selected)
        if not (path / "app.py").exists():
            messagebox.showerror(APP_NAME, "That folder does not contain app.py. Select the Ravynel-Security installation folder.")
            return
        self.root_path = path.resolve()
        self.install_path.set(str(self.root_path))
        self.set_message("Installation folder updated. Press Start to launch the network sensor console.")

    def start(self) -> None:
        if self.process and self.process.poll() is None:
            self.open_console()
            return
        if self.root_path is None or not (self.root_path / "app.py").exists():
            self.choose_folder()
            if self.root_path is None:
                return

        self.lan_ip = detect_lan_ip()
        self.network_ip.set(self.lan_ip)
        self.port = free_port()
        bind_host = "0.0.0.0"
        app_url = f"http://{self.lan_ip}:{self.port}/app"
        local_health = f"http://127.0.0.1:{self.port}/health"
        lan_health = f"http://{self.lan_ip}:{self.port}/health"
        self.console_url.set(app_url)

        logs = self.root_path / "logs"
        logs.mkdir(exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"
        self.out_log = logs / f"gui-{stamp}.out.log"
        self.err_log = logs / f"gui-{stamp}.err.log"
        self.log_path.set(str(self.out_log))

        try:
            (logs / "latest-launch.txt").write_text(
                f"Ravynel GUI launch\nurl={app_url}\nbind={bind_host}:{self.port}\nstdout={self.out_log}\nstderr={self.err_log}\n",
                encoding="utf-8",
            )
        except OSError:
            pass

        with self.out_log.open("w", encoding="utf-8") as out, self.err_log.open("w", encoding="utf-8") as err:
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    "app.py",
                    "dashboard",
                    "--api-host",
                    bind_host,
                    "--api-port",
                    str(self.port),
                    "--no-browser",
                ],
                cwd=str(self.root_path),
                stdout=out,
                stderr=err,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

        self.status.set("Starting")
        self.set_message("Starting Ravynel. Waiting for the local analyzer service to publish the console endpoint...")
        self.refresh_status()
        self.window.update_idletasks()
        if wait_ready([local_health, lan_health], self.process, self.out_log):
            self.status.set("Running")
            self.refresh_status()
            self.set_message(f"Ravynel is running at {app_url}. Open it locally or from another trusted device on the same network if Windows Firewall allows access.")
            webbrowser.open(app_url)
            return

        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.status.set("Stopped")
        self.refresh_status()
        messagebox.showerror(
            APP_NAME,
            "Ravynel did not become ready.\n\n"
            f"Logs:\n{self.out_log}\n{self.err_log}\n\n"
            "If this mentions packet capture, install Npcap and run as Administrator.",
        )

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.set_message("Ravynel sensor stopped. Packet counters should no longer increase after the app refreshes.")
        self.status.set("Stopped")
        self.refresh_status()

    def open_console(self) -> None:
        url = self.console_url.get()
        if url and url != "Not running":
            webbrowser.open(url)
        else:
            self.start()

    def open_logs(self) -> None:
        target = self.err_log or self.out_log
        if target and target.exists():
            os.startfile(str(target))
        elif self.root_path and (self.root_path / "logs").exists():
            os.startfile(str(self.root_path / "logs"))
        else:
            messagebox.showinfo(APP_NAME, "No logs are available yet.")

    def refresh_status(self, schedule: bool = False) -> None:
        running = bool(self.process and self.process.poll() is None)
        if running and self.status.get() != "Starting":
            self.status.set("Running")
        elif not running and self.status.get() != "Starting":
            self.status.set("Stopped")
        if hasattr(self, "status_label"):
            self.status_label.configure(style=self.status_style())
        if hasattr(self, "start_button"):
            self.start_button.configure(state="disabled" if running or self.status.get() == "Starting" else "normal")
            self.stop_button.configure(state="normal" if running else "disabled")
            self.open_button.configure(state="normal" if self.console_url.get() != "Not running" else "disabled")
        self.network_ip.set(detect_lan_ip())
        if schedule:
            self.after_id = self.window.after(2500, lambda: self.refresh_status(schedule=True))

    def about(self) -> None:
        messagebox.showinfo(APP_NAME, "Ravynel NDR\nEnterprise network detection and response console.\nDeveloped by: HeliSudani")

    def on_close(self) -> None:
        if self.process and self.process.poll() is None:
            if not messagebox.askyesno(APP_NAME, "Ravynel is still running. Stop it before closing?"):
                self.window.destroy()
                return
            self.stop()
        self.window.destroy()

    def run(self) -> int:
        self.window.mainloop()
        return 0


def main() -> int:
    app = RavynelControlCenter()
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())


