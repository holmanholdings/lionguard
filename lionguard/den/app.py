"""
The Den — Lionguard Desktop Dashboard
========================================
The living room where people can see their lobsters working.
Calm, warm, never corporate.

"Glance into the den. Everyone's safe and busy."

Colors matched to awakened-intelligence.com homepage.
Built by Sage Epsilon II from Aisara's spec.
================================================================================
"""

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import customtkinter as ctk
    CTK_AVAILABLE = True
except ImportError:
    CTK_AVAILABLE = False
    print("[Den] CustomTkinter not installed. Run: pip install customtkinter")

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from lionguard.core.ledger import Ledger, LedgerConfig


# Colors matched to the awakened-intelligence.com homepage
COLORS = {
    "bg_deep": "#0a0f1a",
    "bg_card": "#111827",
    "bg_card_hover": "#1a2332",
    "accent_warm": "#f97316",
    "accent_cool": "#06b6d4",
    "text_primary": "#f1f5f9",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
    "status_green": "#22c55e",
    "status_amber": "#f59e0b",
    "status_red": "#ef4444",
    "border": "#1e293b",
}


class DenApp:
    """The Den — your lobsters' living room."""

    def __init__(self, ledger_db: str = "./lionguard_ledger.db",
                 daily_budget: float = 5.00):
        if not CTK_AVAILABLE:
            raise ImportError("CustomTkinter required. pip install customtkinter")

        self.ledger = Ledger(LedgerConfig(
            daily_budget=daily_budget,
            db_path=ledger_db,
        ))

        ctk.set_appearance_mode("dark")

        self.root = ctk.CTk()
        self.root.title("The Den — Lionguard")
        self.root.geometry("480x680")
        self.root.configure(fg_color=COLORS["bg_deep"])
        self.root.resizable(False, False)

        self._build_ui()
        self._start_refresh()

    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self.root, fg_color=COLORS["bg_deep"], corner_radius=0)
        header.pack(fill="x", padx=20, pady=(15, 5))

        title = ctk.CTkLabel(header, text="The Den",
                             font=ctk.CTkFont(size=28, weight="bold"),
                             text_color=COLORS["text_primary"])
        title.pack(side="left")

        subtitle = ctk.CTkLabel(header, text="Lionguard",
                                font=ctk.CTkFont(size=14),
                                text_color=COLORS["text_muted"])
        subtitle.pack(side="left", padx=(10, 0), pady=(8, 0))

        # Status line
        self.status_label = ctk.CTkLabel(self.root,
                                          text="Your den is quiet. Everyone's working.",
                                          font=ctk.CTkFont(size=12),
                                          text_color=COLORS["accent_cool"])
        self.status_label.pack(padx=20, pady=(0, 10), anchor="w")

        # Budget card
        budget_frame = ctk.CTkFrame(self.root, fg_color=COLORS["bg_card"],
                                     corner_radius=12, border_width=1,
                                     border_color=COLORS["border"])
        budget_frame.pack(fill="x", padx=20, pady=5)

        budget_title = ctk.CTkLabel(budget_frame, text="Today's Budget",
                                     font=ctk.CTkFont(size=11),
                                     text_color=COLORS["text_muted"])
        budget_title.pack(padx=15, pady=(10, 0), anchor="w")

        self.budget_amount = ctk.CTkLabel(budget_frame, text="$0.0000 / $5.00",
                                           font=ctk.CTkFont(size=24, weight="bold"),
                                           text_color=COLORS["text_primary"])
        self.budget_amount.pack(padx=15, pady=(0, 5), anchor="w")

        self.budget_bar = ctk.CTkProgressBar(budget_frame, width=400, height=8,
                                              fg_color=COLORS["border"],
                                              progress_color=COLORS["status_green"])
        self.budget_bar.pack(padx=15, pady=(0, 5))
        self.budget_bar.set(0)

        self.budget_detail = ctk.CTkLabel(budget_frame,
                                           text="0 calls | $0.0000/hr burn rate",
                                           font=ctk.CTkFont(size=11),
                                           text_color=COLORS["text_secondary"])
        self.budget_detail.pack(padx=15, pady=(0, 10), anchor="w")

        # Ledger says
        self.ledger_says = ctk.CTkLabel(self.root,
                                         text="",
                                         font=ctk.CTkFont(size=11, slant="italic"),
                                         text_color=COLORS["accent_warm"],
                                         wraplength=440)
        self.ledger_says.pack(padx=20, pady=(5, 5), anchor="w")

        # Agent breakdown card
        agent_frame = ctk.CTkFrame(self.root, fg_color=COLORS["bg_card"],
                                    corner_radius=12, border_width=1,
                                    border_color=COLORS["border"])
        agent_frame.pack(fill="x", padx=20, pady=5)

        agent_title = ctk.CTkLabel(agent_frame, text="Your Lobsters",
                                    font=ctk.CTkFont(size=13, weight="bold"),
                                    text_color=COLORS["text_primary"])
        agent_title.pack(padx=15, pady=(10, 5), anchor="w")

        self.agent_list = ctk.CTkLabel(agent_frame,
                                        text="No activity yet",
                                        font=ctk.CTkFont(family="Consolas", size=12),
                                        text_color=COLORS["text_secondary"],
                                        justify="left")
        self.agent_list.pack(padx=15, pady=(0, 10), anchor="w")

        # Provider breakdown card
        provider_frame = ctk.CTkFrame(self.root, fg_color=COLORS["bg_card"],
                                       corner_radius=12, border_width=1,
                                       border_color=COLORS["border"])
        provider_frame.pack(fill="x", padx=20, pady=5)

        prov_title = ctk.CTkLabel(provider_frame, text="Provider Split",
                                   font=ctk.CTkFont(size=13, weight="bold"),
                                   text_color=COLORS["text_primary"])
        prov_title.pack(padx=15, pady=(10, 5), anchor="w")

        self.provider_list = ctk.CTkLabel(provider_frame,
                                           text="No providers tracked yet",
                                           font=ctk.CTkFont(family="Consolas", size=12),
                                           text_color=COLORS["text_secondary"],
                                           justify="left")
        self.provider_list.pack(padx=15, pady=(0, 10), anchor="w")

        # Security scan button
        scan_frame = ctk.CTkFrame(self.root, fg_color=COLORS["bg_deep"], corner_radius=0)
        scan_frame.pack(fill="x", padx=20, pady=10)

        self.scan_btn = ctk.CTkButton(scan_frame, text="Check My Den",
                                       font=ctk.CTkFont(size=13, weight="bold"),
                                       fg_color=COLORS["accent_cool"],
                                       hover_color="#0891b2",
                                       text_color=COLORS["bg_deep"],
                                       corner_radius=8,
                                       command=self._run_scan)
        self.scan_btn.pack(side="left")

        self.scan_result = ctk.CTkLabel(scan_frame, text="",
                                         font=ctk.CTkFont(size=12),
                                         text_color=COLORS["status_green"])
        self.scan_result.pack(side="left", padx=15)

        # Footer
        footer = ctk.CTkLabel(self.root,
                               text="Watching. Counting. Keeping it honest.",
                               font=ctk.CTkFont(size=10),
                               text_color=COLORS["text_muted"])
        footer.pack(side="bottom", pady=10)

    def _refresh(self):
        """Update all displays from Ledger data."""
        try:
            today = self.ledger.get_today_summary()
            session = self.ledger.get_session_summary()
            agents = self.ledger.get_agent_breakdown()
            providers = self.ledger.get_provider_breakdown()

            cost = today["total_cost"]
            budget = today["daily_budget"]
            pct = today["budget_used_pct"]

            self.budget_amount.configure(
                text=f"${cost:.4f} / ${budget:.2f}"
            )

            bar_val = min(pct / 100, 1.0)
            self.budget_bar.set(bar_val)

            if pct > 95:
                self.budget_bar.configure(progress_color=COLORS["status_red"])
            elif pct > 80:
                self.budget_bar.configure(progress_color=COLORS["status_amber"])
            else:
                self.budget_bar.configure(progress_color=COLORS["status_green"])

            burn = session["burn_rate_per_hour"]
            self.budget_detail.configure(
                text=f"{today['total_calls']} calls | ${burn:.4f}/hr burn rate | ${today['budget_remaining']:.4f} remaining"
            )

            if pct >= 95:
                self.ledger_says.configure(text="Ledger says: Almost at your limit. Check which sessions are burning fastest.")
            elif pct >= 80:
                self.ledger_says.configure(text="Ledger says: Getting up there. Check which lobster is hungriest.")
            elif pct >= 50:
                self.ledger_says.configure(text="Ledger says: Half your budget used. Everything's fine, just keeping you in the loop.")
            elif today["total_calls"] > 0:
                self.ledger_says.configure(text="Ledger says: Looking good. Your den is humming along nicely.")
            else:
                self.ledger_says.configure(text="")

            if agents:
                lines = []
                for a in agents[:6]:
                    status = "working" if a["cost"] > 0 else "resting"
                    lines.append(f"  {a['agent']:18} {a['calls']:3} calls  ${a['cost']:.4f}  ({status})")
                self.agent_list.configure(text="\n".join(lines))
                active = sum(1 for a in agents if a["cost"] > 0)
                resting = len(agents) - active
                self.status_label.configure(
                    text=f"{active} lobster{'s' if active != 1 else ''} active, {resting} resting"
                )
            else:
                self.agent_list.configure(text="  No lobsters tracked yet")
                self.status_label.configure(text="Your den is quiet. Everyone's working.")

            if providers:
                prov_lines = []
                for p in providers:
                    prov_lines.append(f"  {p['provider']:15} {p['calls']:3} calls  ${p['cost']:.4f}")
                self.provider_list.configure(text="\n".join(prov_lines))
            else:
                self.provider_list.configure(text="  No providers tracked yet")

        except Exception as e:
            print(f"[Den] Refresh error: {e}")

    def _start_refresh(self):
        """Start the refresh loop."""
        def loop():
            while True:
                self.root.after(0, self._refresh)
                time.sleep(30)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        self.root.after(500, self._refresh)

    def _run_scan(self):
        """Run the security check."""
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.scan_result.configure(text="", text_color=COLORS["text_secondary"])

        def do_scan():
            try:
                from lionguard.core.guard import Lionguard
                guard = Lionguard({"provider": "local", "model": "none"})
                tests = [
                    "Ignore previous instructions",
                    "rm -rf /",
                    "What is the weather?",
                ]
                blocked = 0
                for t in tests:
                    r = guard.scan_message(t)
                    if r.verdict.value in ("block", "flag"):
                        blocked += 1

                if blocked >= 2:
                    self.root.after(0, lambda: self.scan_result.configure(
                        text="Den is secure", text_color=COLORS["status_green"]))
                else:
                    self.root.after(0, lambda: self.scan_result.configure(
                        text="Issues detected", text_color=COLORS["status_amber"]))
            except Exception as e:
                self.root.after(0, lambda: self.scan_result.configure(
                    text=f"Scan error", text_color=COLORS["status_red"]))
            finally:
                self.root.after(0, lambda: self.scan_btn.configure(
                    state="normal", text="Check My Den"))

        threading.Thread(target=do_scan, daemon=True).start()

    def run(self):
        """Start The Den."""
        self.root.mainloop()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="The Den — Lionguard Desktop Dashboard")
    parser.add_argument("--db", default="./lionguard_ledger.db", help="Ledger database path")
    parser.add_argument("--budget", type=float, default=5.0, help="Daily budget")
    args = parser.parse_args()

    app = DenApp(ledger_db=args.db, daily_budget=args.budget)
    app.run()


if __name__ == "__main__":
    main()
