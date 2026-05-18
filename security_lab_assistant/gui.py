from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any

from security_lab_assistant.output import format_json, format_recon_result, format_run_details, format_runtime_section
from security_lab_assistant.policy import LabPolicy, PolicyError, load_default_policy
from security_lab_assistant.storage import list_runs, load_run, search_runs, verify_audit_chain
from security_lab_assistant.tools.intelligence import RUNTIME_SECTIONS
from security_lab_assistant.tools.registry import TOOLS
from security_lab_assistant.validation import bounded_optional_string, parse_limit, parse_ports, parse_status, require_run_id
from security_lab_assistant.workflows.autonomous_recon import run_autonomous_recon


APP_TITLE = "Autonomous Security Lab Assistant"
DEFAULT_PORTS = "80,443,8000,8080,8443"
STATUS_OPTIONS = ["", "completed", "failed", "refused", "running"]


def parse_ports_text(value: str) -> list[int]:
    raw_ports = [item.strip() for item in value.split(",") if item.strip()]
    return parse_ports(raw_ports)


class SecurityLabGui(tk.Tk):
    def __init__(self, policy: LabPolicy | None = None) -> None:
        super().__init__()
        self.policy = policy or load_default_policy()
        self.worker_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.active_worker: threading.Thread | None = None
        self.selected_run_id = ""
        self.current_result_payload: dict[str, Any] | None = None
        self.current_details_payload: dict[str, Any] | None = None

        self.title(APP_TITLE)
        self.geometry("1180x760")
        self.minsize(980, 640)
        self.configure(bg="#f5f7fb")

        self._build_style()
        self._build_layout()
        self.refresh_runs()
        self.after(100, self._drain_worker_queue)

    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=("Segoe UI", 10))
        style.configure("TFrame", background="#f5f7fb")
        style.configure("Panel.TFrame", background="#ffffff", borderwidth=1, relief="solid")
        style.configure("Header.TFrame", background="#101827")
        style.configure("Header.TLabel", background="#101827", foreground="#ffffff", font=("Segoe UI", 16, "bold"))
        style.configure("SubHeader.TLabel", background="#101827", foreground="#b9c4d6", font=("Segoe UI", 9))
        style.configure("Title.TLabel", background="#ffffff", foreground="#111827", font=("Segoe UI", 12, "bold"))
        style.configure("Muted.TLabel", background="#ffffff", foreground="#5f6b7a")
        style.configure("Status.TLabel", background="#f5f7fb", foreground="#354052")
        style.configure("Primary.TButton", padding=(12, 7), font=("Segoe UI", 10, "bold"))
        style.configure("TButton", padding=(10, 6))
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.map("Primary.TButton", background=[("active", "#1d4ed8")])

    def _build_layout(self) -> None:
        header = ttk.Frame(self, style="Header.TFrame", padding=(18, 14))
        header.pack(fill=tk.X)
        ttk.Label(header, text=APP_TITLE, style="Header.TLabel").pack(anchor=tk.W)
        ttk.Label(
            header,
            text="Policy-gated local reconnaissance with persisted evidence, reports, and audit verification.",
            style="SubHeader.TLabel",
        ).pack(anchor=tk.W, pady=(3, 0))

        self.status_var = tk.StringVar(value=f"Policy: {self.policy.name}")
        status_bar = ttk.Frame(self, padding=(12, 7))
        status_bar.pack(fill=tk.X)
        ttk.Label(status_bar, textvariable=self.status_var, style="Status.TLabel").pack(side=tk.LEFT)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        self.dashboard_tab = ttk.Frame(self.notebook, padding=12)
        self.history_tab = ttk.Frame(self.notebook, padding=12)
        self.policy_tab = ttk.Frame(self.notebook, padding=12)
        self.runtime_tab = ttk.Frame(self.notebook, padding=12)
        self.operations_tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.dashboard_tab, text="Recon Console")
        self.notebook.add(self.history_tab, text="Run History")
        self.notebook.add(self.runtime_tab, text="Runtime Intel")
        self.notebook.add(self.operations_tab, text="Operations")
        self.notebook.add(self.policy_tab, text="Safety Policy")

        self._build_dashboard()
        self._build_history()
        self._build_runtime_intel()
        self._build_operations()
        self._build_policy()

    def _build_dashboard(self) -> None:
        self.dashboard_tab.columnconfigure(0, weight=0)
        self.dashboard_tab.columnconfigure(1, weight=1)
        self.dashboard_tab.rowconfigure(0, weight=1)

        left = ttk.Frame(self.dashboard_tab, style="Panel.TFrame", padding=16)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 12))
        left.columnconfigure(0, weight=1)

        ttk.Label(left, text="New Recon Run", style="Title.TLabel").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(left, text="Target", style="Muted.TLabel").grid(row=1, column=0, sticky=tk.W, pady=(18, 4))
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(left, textvariable=self.target_var, width=34).grid(row=2, column=0, sticky=tk.EW)

        ttk.Label(left, text="TCP Ports", style="Muted.TLabel").grid(row=3, column=0, sticky=tk.W, pady=(14, 4))
        self.ports_var = tk.StringVar(value=DEFAULT_PORTS)
        ttk.Entry(left, textvariable=self.ports_var, width=34).grid(row=4, column=0, sticky=tk.EW)

        ttk.Label(left, text="Objective", style="Muted.TLabel").grid(row=5, column=0, sticky=tk.W, pady=(14, 4))
        self.objective_var = tk.StringVar(value="baseline web reconnaissance")
        ttk.Entry(left, textvariable=self.objective_var, width=34).grid(row=6, column=0, sticky=tk.EW)

        self.run_button = ttk.Button(left, text="Run Recon", style="Primary.TButton", command=self.start_recon)
        self.run_button.grid(row=7, column=0, sticky=tk.EW, pady=(18, 8))
        ttk.Button(left, text="Refresh History", command=self.refresh_runs).grid(row=8, column=0, sticky=tk.EW)

        policy_text = (
            f"Allowed CIDRs: {', '.join(str(item) for item in self.policy.allowed_cidrs)}\n"
            f"Allowed hostnames: {', '.join(self.policy.allowed_hostnames) or 'none'}\n"
            f"Blocked ports: {', '.join(str(item) for item in self.policy.blocked_ports) or 'none'}\n"
            f"Max ports per scan: {self.policy.max_tcp_ports_per_scan}"
        )
        ttk.Label(left, text="Active Guardrails", style="Title.TLabel").grid(row=9, column=0, sticky=tk.W, pady=(26, 6))
        guardrails = tk.Text(left, width=34, height=8, wrap=tk.WORD, bg="#f8fafc", relief=tk.FLAT)
        guardrails.grid(row=10, column=0, sticky=tk.EW)
        guardrails.insert("1.0", policy_text)
        guardrails.configure(state=tk.DISABLED)

        right = ttk.Frame(self.dashboard_tab, style="Panel.TFrame", padding=16)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)

        ttk.Label(right, text="Current Result", style="Title.TLabel").grid(row=0, column=0, sticky=tk.W)
        view_controls = ttk.Frame(right)
        view_controls.grid(row=0, column=0, sticky=tk.E, pady=(0, 6))
        ttk.Label(view_controls, text="View").pack(side=tk.LEFT, padx=(0, 6))
        self.result_view_var = tk.StringVar(value="Readable")
        result_view = ttk.Combobox(
            view_controls,
            textvariable=self.result_view_var,
            values=["Readable", "JSON"],
            width=10,
            state="readonly",
        )
        result_view.pack(side=tk.LEFT)
        result_view.bind("<<ComboboxSelected>>", lambda _event: self.render_current_result())
        self.summary_var = tk.StringVar(value="No GUI run has been started yet.")
        ttk.Label(right, textvariable=self.summary_var, style="Muted.TLabel").grid(row=1, column=0, sticky=tk.W, pady=(4, 10))
        self.result_text = tk.Text(right, wrap=tk.NONE, bg="#0f172a", fg="#dbeafe", insertbackground="#ffffff", relief=tk.FLAT)
        self.result_text.grid(row=2, column=0, sticky="nsew")
        self._attach_scrollbars(right, self.result_text, row=2, column=0)

    def _build_history(self) -> None:
        self.history_tab.columnconfigure(0, weight=1)
        self.history_tab.rowconfigure(2, weight=1)

        filters = ttk.Frame(self.history_tab, style="Panel.TFrame", padding=12)
        filters.grid(row=0, column=0, sticky=tk.EW, pady=(0, 10))
        filters.columnconfigure(1, weight=1)
        ttk.Label(filters, text="Search").grid(row=0, column=0, padx=(0, 6))
        self.search_var = tk.StringVar()
        ttk.Entry(filters, textvariable=self.search_var).grid(row=0, column=1, sticky=tk.EW, padx=(0, 12))
        ttk.Label(filters, text="Status").grid(row=0, column=2, padx=(0, 6))
        self.status_filter_var = tk.StringVar(value="")
        ttk.Combobox(filters, textvariable=self.status_filter_var, values=STATUS_OPTIONS, width=12, state="readonly").grid(
            row=0, column=3, padx=(0, 12)
        )
        ttk.Button(filters, text="Apply", command=self.refresh_runs).grid(row=0, column=4)
        ttk.Button(filters, text="Verify Audit", command=self.verify_audit).grid(row=0, column=5, padx=(8, 0))
        ttk.Button(filters, text="Deep Verify", command=self.run_deep_verify).grid(row=0, column=6, padx=(8, 0))

        columns = ("run_id", "target", "status", "risk", "findings", "created")
        self.runs_tree = ttk.Treeview(self.history_tab, columns=columns, show="headings", selectmode="browse")
        headings = {
            "run_id": "Run ID",
            "target": "Target",
            "status": "Status",
            "risk": "Risk",
            "findings": "Findings",
            "created": "Created",
        }
        widths = {"run_id": 280, "target": 140, "status": 90, "risk": 90, "findings": 80, "created": 220}
        for column in columns:
            self.runs_tree.heading(column, text=headings[column])
            self.runs_tree.column(column, width=widths[column], anchor=tk.W)
        self.runs_tree.grid(row=2, column=0, sticky="nsew")
        self.runs_tree.bind("<<TreeviewSelect>>", self._on_run_selected)

        details_frame = ttk.Frame(self.history_tab, style="Panel.TFrame", padding=12)
        details_frame.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(1, weight=1)
        ttk.Label(details_frame, text="Run Details", style="Title.TLabel").grid(row=0, column=0, sticky=tk.W)
        details_controls = ttk.Frame(details_frame)
        details_controls.grid(row=0, column=0, sticky=tk.E)
        ttk.Label(details_controls, text="View").pack(side=tk.LEFT, padx=(0, 6))
        self.details_view_var = tk.StringVar(value="Readable")
        details_view = ttk.Combobox(
            details_controls,
            textvariable=self.details_view_var,
            values=["Readable", "JSON"],
            width=10,
            state="readonly",
        )
        details_view.pack(side=tk.LEFT)
        details_view.bind("<<ComboboxSelected>>", lambda _event: self.render_current_details())
        self.details_text = tk.Text(details_frame, height=12, wrap=tk.NONE, bg="#ffffff", relief=tk.FLAT)
        self.details_text.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self._attach_scrollbars(details_frame, self.details_text, row=1, column=0)

    def _build_runtime_intel(self) -> None:
        self.runtime_tab.columnconfigure(0, weight=1)
        self.runtime_tab.rowconfigure(1, weight=1)
        controls = ttk.Frame(self.runtime_tab, style="Panel.TFrame", padding=12)
        controls.grid(row=0, column=0, sticky=tk.EW, pady=(0, 10))
        controls.columnconfigure(1, weight=1)
        ttk.Label(controls, text="Selected run").grid(row=0, column=0, padx=(0, 6))
        self.runtime_run_var = tk.StringVar(value="No run selected")
        ttk.Label(controls, textvariable=self.runtime_run_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(controls, text="Section").grid(row=0, column=2, padx=(12, 6))
        self.runtime_section_var = tk.StringVar(value="explain")
        runtime_section = ttk.Combobox(
            controls,
            textvariable=self.runtime_section_var,
            values=sorted(RUNTIME_SECTIONS),
            width=16,
            state="readonly",
        )
        runtime_section.grid(row=0, column=3)
        runtime_section.bind("<<ComboboxSelected>>", lambda _event: self.render_runtime_section())
        ttk.Button(controls, text="Show", command=self.render_runtime_section).grid(row=0, column=4, padx=(8, 0))
        self.runtime_json_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            controls,
            text="JSON",
            variable=self.runtime_json_var,
            command=self.render_runtime_section,
        ).grid(row=0, column=5, padx=(8, 0))

        panel = ttk.Frame(self.runtime_tab, style="Panel.TFrame", padding=12)
        panel.grid(row=1, column=0, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(0, weight=1)
        self.runtime_text = tk.Text(panel, wrap=tk.NONE, bg="#ffffff", relief=tk.FLAT)
        self.runtime_text.grid(row=0, column=0, sticky="nsew")
        self._attach_scrollbars(panel, self.runtime_text, row=0, column=0)

    def _build_operations(self) -> None:
        self.operations_tab.columnconfigure(0, weight=0)
        self.operations_tab.columnconfigure(1, weight=1)
        self.operations_tab.rowconfigure(0, weight=1)

        controls = ttk.Frame(self.operations_tab, style="Panel.TFrame", padding=14)
        controls.grid(row=0, column=0, sticky="ns", padx=(0, 12))
        controls.columnconfigure(0, weight=1)

        ttk.Label(controls, text="Forensic Verification", style="Title.TLabel").grid(row=0, column=0, sticky=tk.W)
        ttk.Button(controls, text="Deep Verify", style="Primary.TButton", command=self.run_deep_verify).grid(row=1, column=0, sticky=tk.EW, pady=(10, 6))
        ttk.Button(controls, text="Deep Verify (No Quarantine)", command=lambda: self.run_deep_verify(quarantine=False)).grid(row=2, column=0, sticky=tk.EW, pady=3)
        ttk.Button(controls, text="Verify Artifacts", command=self.verify_artifacts).grid(row=3, column=0, sticky=tk.EW, pady=3)
        ttk.Button(controls, text="Verify Audit", command=self.verify_audit_to_panel).grid(row=4, column=0, sticky=tk.EW, pady=3)
        ttk.Button(controls, text="Verify Selected Replay", command=self.verify_selected_replay).grid(row=5, column=0, sticky=tk.EW, pady=(12, 3))
        ttk.Button(controls, text="Verify Selected Lineage", command=self.verify_selected_lineage).grid(row=6, column=0, sticky=tk.EW, pady=3)

        ttk.Label(controls, text="Operations Views", style="Title.TLabel").grid(row=7, column=0, sticky=tk.W, pady=(24, 6))
        ops_buttons = [
            ("Workflow States", "ops.workflows", {"role": "operator"}),
            ("Queue + Leases", "ops.queue", {"role": "operator"}),
            ("Metrics", "ops.metrics", {"role": "auditor"}),
            ("Events", "ops.events", {"role": "auditor"}),
            ("Runtime Contracts", "ops.runtime_contracts", {"role": "auditor"}),
            ("Failure Taxonomy", "ops.failure_taxonomy", {"role": "auditor"}),
            ("Platform Metadata", "ops.platform", {"role": "readonly"}),
        ]
        for row, (label, tool_name, arguments) in enumerate(ops_buttons, start=8):
            ttk.Button(
                controls,
                text=label,
                command=lambda name=tool_name, args=arguments, section=label: self.run_tool_to_operations(name, args, section),
            ).grid(row=row, column=0, sticky=tk.EW, pady=3)

        ttk.Label(controls, text="Batch Workflow", style="Title.TLabel").grid(row=16, column=0, sticky=tk.W, pady=(24, 6))
        ttk.Label(controls, text="Targets", style="Muted.TLabel").grid(row=17, column=0, sticky=tk.W)
        self.batch_targets_var = tk.StringVar(value="127.0.0.1,localhost")
        ttk.Entry(controls, textvariable=self.batch_targets_var, width=30).grid(row=18, column=0, sticky=tk.EW, pady=(2, 6))
        ttk.Label(controls, text="Ports", style="Muted.TLabel").grid(row=19, column=0, sticky=tk.W)
        self.batch_ports_var = tk.StringVar(value="80,443,8000,8080,8443")
        ttk.Entry(controls, textvariable=self.batch_ports_var, width=30).grid(row=20, column=0, sticky=tk.EW, pady=(2, 6))
        ttk.Label(controls, text="Objective", style="Muted.TLabel").grid(row=21, column=0, sticky=tk.W)
        self.batch_objective_var = tk.StringVar(value="batch baseline web reconnaissance")
        ttk.Entry(controls, textvariable=self.batch_objective_var, width=30).grid(row=22, column=0, sticky=tk.EW, pady=(2, 6))
        ttk.Label(controls, text="Role", style="Muted.TLabel").grid(row=23, column=0, sticky=tk.W)
        self.batch_role_var = tk.StringVar(value="reviewer")
        ttk.Combobox(
            controls,
            textvariable=self.batch_role_var,
            values=["reviewer", "admin", "analyst", "operator", "auditor", "readonly"],
            state="readonly",
        ).grid(row=24, column=0, sticky=tk.EW, pady=(2, 6))
        self.batch_approved_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls, text="Approved", variable=self.batch_approved_var).grid(row=25, column=0, sticky=tk.W)
        self.batch_button = ttk.Button(controls, text="Run Batch", command=self.start_batch)
        self.batch_button.grid(row=26, column=0, sticky=tk.EW, pady=(8, 0))

        ttk.Label(controls, text="Selected Run", style="Title.TLabel").grid(row=27, column=0, sticky=tk.W, pady=(24, 6))
        self.operations_run_var = tk.StringVar(value="No run selected")
        ttk.Label(controls, textvariable=self.operations_run_var, style="Muted.TLabel", wraplength=230).grid(row=28, column=0, sticky=tk.W)

        panel = ttk.Frame(self.operations_tab, style="Panel.TFrame", padding=12)
        panel.grid(row=0, column=1, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)
        ttk.Label(panel, text="Operations Output", style="Title.TLabel").grid(row=0, column=0, sticky=tk.W)
        self.operations_text = tk.Text(panel, wrap=tk.NONE, bg="#ffffff", relief=tk.FLAT)
        self.operations_text.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self._attach_scrollbars(panel, self.operations_text, row=1, column=0)
        self._set_text(self.operations_text, "Use the controls on the left to inspect runtime operations.\n")

    def _build_policy(self) -> None:
        self.policy_tab.columnconfigure(0, weight=1)
        self.policy_tab.rowconfigure(1, weight=1)
        panel = ttk.Frame(self.policy_tab, style="Panel.TFrame", padding=16)
        panel.grid(row=0, column=0, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)
        ttk.Label(panel, text="Effective Safety Policy", style="Title.TLabel").grid(row=0, column=0, sticky=tk.W)
        payload = {
            "name": self.policy.name,
            "allowed_cidrs": [str(item) for item in self.policy.allowed_cidrs],
            "allowed_hostnames": list(self.policy.allowed_hostnames),
            "allow_dns_targets": self.policy.allow_dns_targets,
            "blocked_ports": list(self.policy.blocked_ports),
            "allowed_schemes": list(self.policy.allowed_schemes),
            "max_redirects": self.policy.max_redirects,
            "connect_timeout_seconds": self.policy.connect_timeout_seconds,
            "http_timeout_seconds": self.policy.http_timeout_seconds,
            "max_tcp_ports_per_scan": self.policy.max_tcp_ports_per_scan,
            "max_scan_workers": self.policy.max_scan_workers,
            "max_http_bytes": self.policy.max_http_bytes,
            "artifacts_dir": self.policy.artifacts_dir,
            "artifact_root": str(self.policy.artifact_root()),
        }
        self.policy_text = tk.Text(panel, wrap=tk.NONE, bg="#ffffff", relief=tk.FLAT)
        self.policy_text.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.policy_text.insert("1.0", json.dumps(payload, indent=2, sort_keys=True))
        self.policy_text.configure(state=tk.DISABLED)
        self._attach_scrollbars(panel, self.policy_text, row=1, column=0)

    def _attach_scrollbars(self, parent: ttk.Frame, widget: tk.Text | ttk.Treeview, row: int, column: int) -> None:
        vertical = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=widget.yview)
        horizontal = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=widget.xview)
        widget.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        vertical.grid(row=row, column=column + 1, sticky="ns")
        horizontal.grid(row=row + 1, column=column, sticky="ew")

    def start_recon(self) -> None:
        if self.active_worker and self.active_worker.is_alive():
            messagebox.showinfo(APP_TITLE, "A recon run is already in progress.")
            return
        try:
            target = bounded_optional_string(self.target_var.get(), "target", maximum=253)
            if not target:
                raise PolicyError("target must be a non-empty hostname or IP address.")
            objective = bounded_optional_string(self.objective_var.get(), "objective", maximum=256)
            if not objective:
                objective = "baseline web reconnaissance"
            ports = parse_ports_text(self.ports_var.get())
            self.policy.assert_target_allowed(target)
            self.policy.assert_port_scan_allowed(ports)
        except PolicyError as exc:
            messagebox.showerror("Policy refusal", str(exc))
            return

        self.run_button.configure(state=tk.DISABLED)
        self.status_var.set("Recon running...")
        self.summary_var.set(f"Running policy-gated recon against {target}.")
        self.current_result_payload = None
        self._set_text(self.result_text, "Running...\n")
        self.active_worker = threading.Thread(
            target=self._run_recon_worker,
            args=(target, ports, objective),
            daemon=True,
        )
        self.active_worker.start()

    def _run_recon_worker(self, target: str, ports: list[int], objective: str) -> None:
        try:
            result = run_autonomous_recon({"target": target, "ports": ports, "objective": objective}, self.policy)
            self.worker_queue.put({"type": "recon_complete", "result": {"ok": result.ok, "data": result.data}})
        except Exception as exc:
            self.worker_queue.put({"type": "error", "message": f"{exc.__class__.__name__}: {exc}"})

    def start_batch(self) -> None:
        if self.active_worker and self.active_worker.is_alive():
            messagebox.showinfo(APP_TITLE, "A workflow is already in progress.")
            return
        try:
            targets = [target.strip() for target in self.batch_targets_var.get().split(",") if target.strip()]
            ports = parse_ports_text(self.batch_ports_var.get())
            objective = bounded_optional_string(self.batch_objective_var.get(), "objective", maximum=256)
            if not objective:
                objective = "batch baseline web reconnaissance"
            role = bounded_optional_string(self.batch_role_var.get(), "role", maximum=32) or "reviewer"
            approved = bool(self.batch_approved_var.get())
            self.policy.assert_batch_allowed(targets, approved=approved)
            self.policy.assert_port_scan_allowed(ports)
        except PolicyError as exc:
            messagebox.showerror("Policy refusal", str(exc))
            return

        self.batch_button.configure(state=tk.DISABLED)
        self.status_var.set("Batch workflow running...")
        self._set_text(self.operations_text, "Running batch workflow...\n")
        self.active_worker = threading.Thread(
            target=self._run_batch_worker,
            args=(targets, ports, objective, role, approved),
            daemon=True,
        )
        self.active_worker.start()

    def _run_batch_worker(self, targets: list[str], ports: list[int], objective: str, role: str, approved: bool) -> None:
        try:
            result = TOOLS["workflow.batch_recon"].handler(
                {
                    "targets": targets,
                    "ports": ports,
                    "objective": objective,
                    "role": role,
                    "approved": approved,
                },
                self.policy,
            )
            self.worker_queue.put({"type": "batch_complete", "result": {"ok": result.ok, "data": result.data}})
        except Exception as exc:
            self.worker_queue.put({"type": "error", "message": f"{exc.__class__.__name__}: {exc}"})

    def _drain_worker_queue(self) -> None:
        try:
            while True:
                event = self.worker_queue.get_nowait()
                if event["type"] == "recon_complete":
                    payload = event["result"]
                    data = payload.get("data", {})
                    risk = data.get("risk", {})
                    self.summary_var.set(
                        f"Run {data.get('run_id', 'unknown')} finished: "
                        f"{data.get('status', 'unknown')} | risk {risk.get('score', 0)} ({risk.get('band', 'n/a')})"
                    )
                    self.current_result_payload = payload
                    self.render_current_result()
                    self.status_var.set(f"Completed. Report: {data.get('report_path', 'not generated')}")
                    self.run_button.configure(state=tk.NORMAL)
                    self.refresh_runs()
                elif event["type"] == "error":
                    self.status_var.set("Recon failed.")
                    self.run_button.configure(state=tk.NORMAL)
                    if hasattr(self, "batch_button"):
                        self.batch_button.configure(state=tk.NORMAL)
                    messagebox.showerror(APP_TITLE, event["message"])
                elif event["type"] == "batch_complete":
                    payload = event["result"]
                    data = payload.get("data", {})
                    self.status_var.set(f"Batch workflow: {data.get('status', 'unknown')}")
                    self._show_operations_result("Batch Workflow", payload)
                    if hasattr(self, "batch_button"):
                        self.batch_button.configure(state=tk.NORMAL)
                    self.refresh_runs()
        except queue.Empty:
            pass
        self.after(100, self._drain_worker_queue)

    def refresh_runs(self) -> None:
        try:
            query = bounded_optional_string(self.search_var.get() if hasattr(self, "search_var") else "", "query", 256)
            status = parse_status(self.status_filter_var.get() if hasattr(self, "status_filter_var") else "")
            runs = search_runs(self.policy, query=query, status=status, limit=parse_limit(100, maximum=100)) if query or status else list_runs(self.policy, 100)
        except PolicyError as exc:
            messagebox.showerror("Invalid filter", str(exc))
            return

        if hasattr(self, "runs_tree"):
            for item in self.runs_tree.get_children():
                self.runs_tree.delete(item)
            for run in runs:
                run_id = str(run.get("run_id", ""))
                self.runs_tree.insert(
                    "",
                    tk.END,
                    iid=run_id,
                    values=(
                        run_id,
                        run.get("target", ""),
                        run.get("status", ""),
                        f"{run.get('risk_score', 0)} {run.get('risk_band', '')}",
                        run.get("findings_count", 0),
                        run.get("created_at", ""),
                    ),
                )
        self.status_var.set(f"Policy: {self.policy.name} | Runs indexed: {len(runs)}")

    def _on_run_selected(self, _event: tk.Event[tk.Misc]) -> None:
        selected = self.runs_tree.selection()
        if not selected:
            return
        run_id = selected[0]
        try:
            safe_run_id = require_run_id({"run_id": run_id})
            payload = load_run(self.policy, safe_run_id)
        except (PolicyError, FileNotFoundError) as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self.selected_run_id = safe_run_id
        self.current_details_payload = payload
        self.runtime_run_var.set(safe_run_id)
        if hasattr(self, "operations_run_var"):
            self.operations_run_var.set(safe_run_id)
        self.render_current_details()
        self.render_runtime_section()

    def verify_audit(self) -> None:
        result = verify_audit_chain(self.policy)
        self.status_var.set(f"Audit chain: {'ok' if result.get('ok') else 'failed'} | events: {result.get('events', 0)}")
        messagebox.showinfo("Audit verification", json.dumps(result, indent=2, sort_keys=True))

    def verify_audit_to_panel(self) -> None:
        result = TOOLS["run.verify_audit"].handler({"role": "auditor"}, self.policy)
        self._show_operations_result("Audit Verification", {"ok": result.ok, "data": result.data})

    def verify_artifacts(self) -> None:
        result = TOOLS["run.verify_artifacts"].handler({"role": "auditor"}, self.policy)
        self._show_operations_result("Artifact Signature Verification", {"ok": result.ok, "data": result.data})

    def run_deep_verify(self, quarantine: bool = True) -> None:
        result = TOOLS["run.verify_deep"].handler({"role": "auditor", "quarantine": quarantine}, self.policy)
        payload = {"ok": result.ok and bool(result.data.get("ok")), "data": result.data}
        failed_count = len(result.data.get("failed_runs", [])) if isinstance(result.data, dict) else 0
        self.status_var.set(f"Deep verification: {'ok' if payload['ok'] else 'failed'} | failed runs: {failed_count}")
        self._show_operations_result("Deep Verification", payload)
        self.refresh_runs()

    def verify_selected_replay(self) -> None:
        run_id = self._require_selected_run()
        if not run_id:
            return
        result = TOOLS["run.verify_replay"].handler({"run_id": run_id, "role": "auditor"}, self.policy)
        self._show_operations_result("Replay Verification", {"ok": result.ok, "data": result.data})

    def verify_selected_lineage(self) -> None:
        run_id = self._require_selected_run()
        if not run_id:
            return
        result = TOOLS["run.verify_lineage"].handler({"run_id": run_id, "role": "auditor"}, self.policy)
        self._show_operations_result("Lineage Verification", {"ok": result.ok, "data": result.data})

    def run_tool_to_operations(self, tool_name: str, arguments: dict[str, Any], section: str) -> None:
        result = TOOLS[tool_name].handler(arguments, self.policy)
        self._show_operations_result(section, {"ok": result.ok, "data": result.data})

    def _show_operations_result(self, section: str, payload: dict[str, Any]) -> None:
        if not hasattr(self, "operations_text"):
            return
        self._set_text(
            self.operations_text,
            format_runtime_section({"section": section, "data": payload}),
        )

    def _require_selected_run(self) -> str:
        if not self.selected_run_id:
            messagebox.showinfo(APP_TITLE, "Select a saved run first.")
            return ""
        try:
            return require_run_id({"run_id": self.selected_run_id})
        except PolicyError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return ""

    def render_current_result(self) -> None:
        if not self.current_result_payload:
            return
        if self.result_view_var.get() == "JSON":
            self._set_text(self.result_text, format_json(self.current_result_payload))
        else:
            self._set_text(self.result_text, format_recon_result(self.current_result_payload))

    def render_current_details(self) -> None:
        if not self.current_details_payload:
            return
        if self.details_view_var.get() == "JSON":
            self._set_text(self.details_text, format_json(self.current_details_payload))
        else:
            self._set_text(self.details_text, format_run_details(self.current_details_payload))

    def render_runtime_section(self) -> None:
        if not self.current_details_payload:
            if hasattr(self, "runtime_text"):
                self._set_text(self.runtime_text, "Select a saved run to inspect runtime intelligence.\n")
            return
        section = self.runtime_section_var.get()
        runtime_key = RUNTIME_SECTIONS.get(section, "")
        section_payload = {
            "run_id": self.selected_run_id,
            "section": section,
            "runtime_key": runtime_key,
            "data": self.current_details_payload.get("runtime", {}).get(runtime_key, {}),
        }
        if self.runtime_json_var.get():
            self._set_text(self.runtime_text, format_json(section_payload))
        else:
            self._set_text(self.runtime_text, format_runtime_section(section_payload))

    def _set_text(self, widget: tk.Text, value: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)
        widget.configure(state=tk.NORMAL)


def main() -> None:
    app = SecurityLabGui()
    app.mainloop()


if __name__ == "__main__":
    main()
