import customtkinter as ctk
import threading
from inspector import DnssecChainCollector
from cli import ReportGenerator

# Setări de aspect
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class DnssecApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configurarea ferestrei principale
        self.title("DNSSEC Inspector Q.R.F.")
        self.geometry("950x750")

        # Layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- HEADER ---
        self.header_frame = ctk.CTkFrame(self)
        self.header_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")

        self.label_title = ctk.CTkLabel(self.header_frame, text="DNSSEC Inspector", font=("Roboto", 24, "bold"))
        self.label_title.pack(pady=5)

        self.label_subtitle = ctk.CTkLabel(self.header_frame, text="Quick Reaction Force Tool", font=("Roboto", 14))
        self.label_subtitle.pack(pady=(0, 10))

        # --- INPUT ---
        self.input_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.input_frame.pack(pady=10)

        self.entry_domain = ctk.CTkEntry(self.input_frame, placeholder_text="ex: ietf.org", width=300)
        self.entry_domain.grid(row=0, column=0, padx=10)

        self.option_type = ctk.CTkOptionMenu(self.input_frame, values=["A", "AAAA", "MX", "NS", "TXT"])
        self.option_type.grid(row=0, column=1, padx=10)

        self.btn_scan = ctk.CTkButton(self.input_frame, text="🔍 INSPECT", command=self.start_scan_thread, font=("Roboto", 14, "bold"))
        self.btn_scan.grid(row=0, column=2, padx=10)

        # --- OUTPUT ---
        # Folosire font monospaced pentru alinierea tabelelor
        self.textbox = ctk.CTkTextbox(self, font=("Consolas", 14))
        self.textbox.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.textbox.insert("0.0", "Ready to inspect.\n\nTry: ietf.org (Secure)\nTry: dnssec-failed.org (Bogus)\nTry: google.com (Insecure/No DS)")

        # --- STATUS BAR ---
        self.status_label = ctk.CTkLabel(self, text="System Ready", text_color="gray", font=("Roboto", 12, "bold"))
        self.status_label.grid(row=2, column=0, pady=5)

    def start_scan_thread(self):
        """Rulează scanarea pe un thread separat."""
        domain = self.entry_domain.get()
        if not domain:
            return
        
        self.btn_scan.configure(state="disabled", text="Scanning...")
        self.status_label.configure(text=f"Inspecting {domain}...", text_color="#3498db")
        
        # Golim textul și arătăm că lucrăm
        self.textbox.configure(state="normal")
        self.textbox.delete("0.0", "end")
        self.textbox.insert("0.0", "Working on it...\n")
        self.textbox.configure(state="disabled")

        thread = threading.Thread(target=self.run_logic, args=(domain, self.option_type.get()))
        thread.start()

    def run_logic(self, domain, rrtype):
        try:
            collector = DnssecChainCollector(timeoutSeconds=3.0)
            trace = collector.inspectDomain(domain, rrtype)
            report = ReportGenerator.to_markdown(trace)
            self.after(0, self.update_gui, report, trace.chainVerdict)
            
        except Exception as e:
            self.after(0, self.update_gui, f"Error: {str(e)}", "ERROR")

    def update_gui(self, report_text, verdict):
        """Funcția care actualizează textul și aplică culorile (Tags)."""
        self.textbox.configure(state="normal")
        self.textbox.delete("0.0", "end")
        self.textbox.insert("0.0", report_text)

        # 1. Definim stilurile de culori (Tags)
        # Accesăm widget-ul intern Tkinter (_textbox) pentru tag-uri avansate
        self.textbox._textbox.tag_config("green", foreground="#00E676")  # Verde Neon
        self.textbox._textbox.tag_config("red", foreground="#FF1744")    # Roșu Aprins
        self.textbox._textbox.tag_config("yellow", foreground="#FFEA00") # Galben
        self.textbox._textbox.tag_config("bold", font=("Consolas", 15, "bold"))

        # 2. Lista de cuvinte de colorat
        patterns = [
            ("✅", "green"), ("OK", "green"), ("Lanț Securizat", "green"), ("SECURE", "green"),
            ("❌", "red"), ("FAIL", "red"), ("BOGUS", "red"), ("Lanț Rupt", "red"), ("DEPRECATED", "red"), ("BROKEN", "red"),
            ("⚠️", "yellow"), ("Nesecurizat", "yellow"), ("INSECURE", "yellow"), ("INDETERMINATE", "yellow")
        ]

        # 3. Căutăm și aplicăm culorile
        text_content = self.textbox.get("0.0", "end")
        
        for pattern, tag in patterns:
            start_index = "1.0"
            while True:
                # Căutăm poziția cuvântului
                pos = self.textbox.search(pattern, start_index, stopindex="end")
                if not pos:
                    break
                
                # Calculăm poziția de final a cuvântului
                # (Line.Col) -> descompunem pentru a adăuga lungimea
                line, char = map(int, pos.split("."))
                end_pos = f"{line}.{char + len(pattern)}"
                
                # Aplicăm tag-ul (culoarea)
                self.textbox.tag_add(tag, pos, end_pos)
                
                # Actualizăm indexul de start pentru următoarea căutare
                start_index = end_pos

        # Colorăm titlurile (liniile care încep cu #)
        start_index = "1.0"
        while True:
            pos = self.textbox.search("#", start_index, stopindex="end")
            if not pos: break
            line, _ = map(int, pos.split("."))
            # Tot rândul bold
            self.textbox.tag_add("bold", f"{line}.0", f"{line}.end")
            start_index = f"{line + 1}.0"


        # Actualizăm status bar-ul
        color = "gray"
        if "SECURE" in verdict:
            color = "#2ecc71"
        elif "BOGUS" in verdict or "BROKEN" in verdict:
            color = "#e74c3c"
        elif "INSECURE" in verdict:
            color = "#f1c40f"

        self.status_label.configure(text=f"Verdict Final: {verdict}", text_color=color)
        self.btn_scan.configure(state="normal", text="🔍 INSPECT")
        self.textbox.configure(state="disabled") # Blocăm editarea

if __name__ == "__main__":
    app = DnssecApp()
    app.mainloop()