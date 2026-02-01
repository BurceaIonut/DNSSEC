import customtkinter as ctk
import threading
from inspector import DnssecChainCollector
from cli import ReportGenerator

# Setări generale (Dark Mode)
ctk.set_appearance_mode("Dark")

accent_color = "#1f538d" 
hover_color = "#14375e"
bg_card = "#2b2b2b" 
text_console = "#E0E0E0" 

class DnssecApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DNSSEC Q.R.F. Inspector")
        self.geometry("1100x850")
        self.minsize(900, 700)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1) 

        self.font_header = ctk.CTkFont(family="Roboto", size=22, weight="bold")
        self.font_label = ctk.CTkFont(family="Roboto", size=14)
        self.font_console = ctk.CTkFont(family="Consolas", size=15) 

        self.setup_navbar()
        self.setup_control_panel()
        self.setup_results_console()

    def setup_navbar(self):
        """Bara de navigare sus."""
        self.navbar_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.navbar_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        
        self.label_logo = ctk.CTkLabel(self.navbar_frame, text="🛡️ DNSSEC INSPECTOR", font=self.font_header, text_color="white")
        self.label_logo.pack(side="left")
        
        self.label_sub = ctk.CTkLabel(self.navbar_frame, text="Quick Reaction Force Tool", font=self.font_label, text_color="gray")
        self.label_sub.pack(side="left", padx=10, pady=(5,0))

    def setup_control_panel(self):
        """Panoul de control (Input)."""
        self.control_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=bg_card)
        self.control_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=10)

        lbl_domain = ctk.CTkLabel(self.control_frame, text="TARGET DOMAIN", font=self.font_label, text_color="silver")
        lbl_domain.grid(row=0, column=0, padx=20, pady=(15, 0), sticky="w")

        lbl_type = ctk.CTkLabel(self.control_frame, text="RECORD TYPE", font=self.font_label, text_color="silver")
        lbl_type.grid(row=0, column=1, padx=20, pady=(15, 0), sticky="w")

        self.entry_domain = ctk.CTkEntry(self.control_frame, placeholder_text="ietf.org", width=400, height=35, font=self.font_label)
        self.entry_domain.grid(row=1, column=0, padx=20, pady=(5, 20))

        self.option_type = ctk.CTkOptionMenu(self.control_frame, values=["A", "AAAA", "MX", "NS", "TXT"], width=150, height=35, 
                                             font=self.font_label, fg_color=accent_color, button_hover_color=hover_color)
        self.option_type.grid(row=1, column=1, padx=20, pady=(5, 20))

        self.btn_scan = ctk.CTkButton(self.control_frame, text="RUN INSPECTION", command=self.start_scan_thread, 
                                      width=200, height=45, font=ctk.CTkFont(size=16, weight="bold"),
                                      fg_color=accent_color, hover_color=hover_color)
        self.btn_scan.grid(row=0, rowspan=2, column=2, padx=20, pady=20)

    def setup_results_console(self):
        """Zona de rezultate (Consola)."""
        self.results_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=bg_card)
        self.results_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(10, 20))
        self.results_frame.grid_columnconfigure(0, weight=1)
        self.results_frame.grid_rowconfigure(1, weight=1)

        self.status_bar = ctk.CTkFrame(self.results_frame, height=40, corner_radius=10, fg_color="#3a3a3a")
        self.status_bar.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        self.status_label = ctk.CTkLabel(self.status_bar, text="STATUS: IDLE | WAITING FOR INPUT", font=self.font_label, text_color="white")
        self.status_label.pack(side="left", padx=15)

        self.textbox = ctk.CTkTextbox(self.results_frame, font=self.font_console, text_color=text_console, 
                                      fg_color=bg_card, border_width=0, corner_radius=5)
        self.textbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        intro_text = (
            "\n  DNSSEC INSPECTOR CONSOLE_V1.0\n"
            "  \n"
            "  System ready. Analyzes Chain of Trust.\n\n"
            "  SCENARIOS:\n"
            "  >> ietf.org            (Secure Chain)\n"
            "  >> dnssec-failed.org   (Broken Chain)\n"
            "  >> cnn.com             (Insecure)\n"
        )
        self.textbox.insert("0.0", intro_text)
        self.textbox.configure(state="disabled")

    def start_scan_thread(self):
        """Execută scanarea în background."""
        domain = self.entry_domain.get()
        if not domain: return
        
        self.btn_scan.configure(state="disabled", text="PROCESSING...")
        self.status_bar.configure(fg_color=accent_color)
        self.status_label.configure(text=f"STATUS: INSPECTING NETWORK >> {domain}")
        
        self.textbox.configure(state="normal")
        self.textbox.delete("0.0", "end")
        self.textbox.insert("0.0", "\n  [>] Initializing DnssecChainCollector...\n  [>] Sending queries (DO=1)...\n  [>] Awaiting response...\n")
        self.textbox.configure(state="disabled")

        thread = threading.Thread(target=self.run_logic, args=(domain, self.option_type.get()))
        thread.start()

    def run_logic(self, domain, rrtype):
        """Logica de business."""
        try:
            collector = DnssecChainCollector(timeoutSeconds=3.5)
            trace = collector.inspectDomain(domain, rrtype)
            report = ReportGenerator.to_markdown(trace)
            self.after(0, self.update_gui, report, trace.chainVerdict)
        except Exception as e:
            self.after(0, self.update_gui_error, str(e))

    def update_gui_error(self, error_msg):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", f"\n\n[!!] SYSTEM ERROR:\n{error_msg}")
        self.textbox.configure(state="disabled")
        self.status_label.configure(text="STATUS: SYSTEM ERROR")
        self.status_bar.configure(fg_color="#c62828")
        self.btn_scan.configure(state="normal", text="RUN INSPECTION")

    def update_gui(self, report_text, verdict):
        """Actualizează interfața cu rezultatul final."""
       
        
        self.textbox.configure(state="normal")
        self.textbox.delete("0.0", "end")
        self.textbox.insert("0.0", report_text)
        self.apply_color_tags() 

        status_color = "#424242" 
        status_text = f"STATUS: DONE // VERDICT: {verdict}"

        if "SECURE" in verdict:
            status_color = "#2e7d32" 
            status_text = f"STATUS: [OK] SECURE CHAIN CONFIRMED ({verdict})"
        elif "BOGUS" in verdict or "BROKEN" in verdict or "MISMATCH" in verdict:
            status_color = "#c62828" 
            status_text = f"STATUS: [XX] SECURITY FAILURE DETECTED ({verdict})"
        elif "INSECURE" in verdict:
            status_color = "#f57f17" 
            status_text = f"STATUS: [!!] DELEGATION INSECURE ({verdict})"

        self.status_bar.configure(fg_color=status_color)
        self.status_label.configure(text=status_text)
        self.btn_scan.configure(state="normal", text="RUN INSPECTION")
        self.textbox.configure(state="disabled")

    def apply_color_tags(self):
        """Aplică culorile în consolă."""
        tb = self.textbox._textbox
        # Definire stiluri (culori)
        tb.tag_config("green", foreground="#00ff9f")
        tb.tag_config("red", foreground="#ff3860")
        tb.tag_config("yellow", foreground="#ffd700")
        tb.tag_config("cyan", foreground="#00d2ff", font=("Consolas", 15, "bold"))
        tb.tag_config("subtle", foreground="#7f8c8d") 
        tb.tag_config("separator", foreground="#555555") 

        patterns = [
            ("[OK]", "green"), ("SECURE", "green"), ("VALID", "green"),
            ("[XX]", "red"), ("FAIL", "red"), ("BOGUS", "red"), ("MISMATCH", "red"), ("CRITICAL", "red"), ("STOPPED", "red"), ("[STOP]", "red"), ("ERROR", "red"),
            ("[!!]", "yellow"), ("INSECURE", "yellow"), ("INDETERMINATE", "yellow"), ("NODATA", "yellow"), ("UNVERIFIED", "yellow")
        ]

        for pattern, tag in patterns:
            start = "1.0"
            while True:
                pos = self.textbox.search(pattern, start, stopindex="end")
                if not pos: break
                line, char = map(int, pos.split("."))
                end = f"{line}.{char + len(pattern)}"
                self.textbox.tag_add(tag, pos, end)
                start = end
        
        start = "1.0"
        while True:
            # Căutăm începutul cutiei
            pos = self.textbox.search("╔", start, stopindex="end")
            if not pos: break
            # Căutăm sfârșitul cutiei
            end_box = self.textbox.search("╝", pos, stopindex="end")
            if end_box:
                self.textbox.tag_add("cyan", pos, f"{end_box}+1c")
                start = f"{end_box}+1c"
            else:
                start = f"{pos}+1c"

        start = "1.0"
        while True:
            pos = self.textbox.search("-->>", start, stopindex="end")
            if not pos: break
            line, char = map(int, pos.split("."))
            end = f"{line}.{char + 4}"
            self.textbox.tag_add("subtle", pos, end)
            start = end
        
        start = "1.0"
        while True:
            pos = self.textbox.search("#", start, stopindex="end")
            if not pos: break
            line, char = map(int, pos.split("."))
            end = f"{line}.{char + 3}"
            self.textbox.tag_add("cyan", pos, end)
            start = end

if __name__ == "__main__":
    app = DnssecApp()
    app.mainloop()