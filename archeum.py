import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import subprocess
import platform
import socket
import psutil
from password_strength import PasswordPolicy

class Application:
    def __init__(self, root):
        self.root = root
        self.root.title("Connexion")
        self.create_login_window()

    def create_login_window(self):
        self.frame_login = ttk.Frame(self.root, padding=20)
        self.frame_login.grid(row=0, column=0, padx=100, pady=50)

        ttk.Label(self.frame_login, text="Nom d'utilisateur:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.entry_username = ttk.Entry(self.frame_login)
        self.entry_username.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.frame_login, text="Mot de passe:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.entry_password = ttk.Entry(self.frame_login, show="*")
        self.entry_password.grid(row=1, column=1, padx=5, pady=5)

        self.button_connect = ttk.Button(self.frame_login, text="Se connecter", command=self.connect)
        self.button_connect.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

    def connect(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        if username == "admin" and password == "password":
            messagebox.showinfo("Connexion réussie", "Connexion réussie en tant qu'administrateur.")
            self.open_main_window()
        else:
            messagebox.showerror("Erreur de connexion", "Nom d'utilisateur ou mot de passe incorrect.")

    def open_main_window(self):
        self.root.destroy()  # Fermer la fenêtre de connexion
        root_main = tk.Tk()
        root_main.title("Outils d'analyse")

        notebook = ttk.Notebook(root_main)
        notebook.pack(fill='both', expand=True)

        self.create_analysis_tab(notebook)
        self.create_firewall_tab(notebook)
        self.create_security_tab(notebook)

        root_main.mainloop()

    def create_analysis_tab(self, notebook):
        frame_analysis = ttk.Frame(notebook)
        notebook.add(frame_analysis, text='Analyse réseau')

        ttk.Label(frame_analysis, text="Adresse IP:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.entry_ip = ttk.Entry(frame_analysis)
        self.entry_ip.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame_analysis, text="Domaine:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.entry_domain = ttk.Entry(frame_analysis)
        self.entry_domain.grid(row=1, column=1, padx=5, pady=5)

        global text_output
        text_output = tk.Text(frame_analysis, height=10, width=50)
        text_output.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        ttk.Button(frame_analysis, text="Exécuter Nmap", command=self.run_nmap).grid(row=3, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(frame_analysis, text="Résoudre le domaine", command=self.resolve_domain).grid(row=3, column=1, padx=5, pady=5, sticky="ew")

    def create_firewall_tab(self, notebook):
        frame_firewall = ttk.Frame(notebook)
        notebook.add(frame_firewall, text='Gestion du pare-feu')

        ttk.Label(frame_firewall, text="Configuration du pare-feu").grid(row=0, column=0, padx=5, pady=5, columnspan=2)

        self.selected_firewall = tk.StringVar(value="Pare-feu Windows")
        firewall_options = ["Pare-feu Windows", "Pare-feu Linux", "Pare-feu MacOS"]

        for index, option in enumerate(firewall_options):
            ttk.Radiobutton(frame_firewall, text=option, variable=self.selected_firewall, value=option).grid(row=index+1, column=0, padx=5, pady=5, sticky="w")

        ttk.Button(frame_firewall, text="Configurer le pare-feu", command=self.configure_firewall).grid(row=len(firewall_options)+1, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(frame_firewall, text="Vérifier le pare-feu", command=self.check_firewall_status).grid(row=len(firewall_options)+2, column=0, padx=5, pady=5, sticky="ew")

    def create_security_tab(self, notebook):
        frame_security = ttk.Frame(notebook)
        notebook.add(frame_security, text='Sécurité')

        ttk.Label(frame_security, text="Vérification de la sécurité").grid(row=0, column=0, padx=5, pady=5)

        ttk.Label(frame_security, text="Mot de passe:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.entry_password_security = ttk.Entry(frame_security, show="*")
        self.entry_password_security.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(frame_security, text="Vérifier la force du mot de passe", command=self.check_password_strength).grid(row=1, column=2, padx=5, pady=5)
        ttk.Button(frame_security, text="Vérifier les vulnérabilités", command=self.check_vulnerabilities).grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        ttk.Button(frame_security, text="Informations système", command=self.show_system_info).grid(row=3, column=0, columnspan=3, padx=5, pady=5)

    def run_nmap(self):
        ip_address = self.entry_ip.get()
        command = ['nmap', ip_address]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        text_output.delete('1.0', tk.END)
        text_output.insert(tk.END, output.decode('utf-8', errors='ignore'))

    def resolve_domain(self):
        domain = self.entry_domain.get()
        try:
            ip_address = socket.gethostbyname(domain)
            text_output.delete('1.0', tk.END)
            text_output.insert(tk.END, f"Adresse IP de {domain}: {ip_address}")
        except socket.gaierror:
            messagebox.showerror("Erreur de résolution DNS", f"Impossible de résoudre le domaine {domain}")

    def configure_firewall(self):
        selected_option = self.selected_firewall.get()
        messagebox.showinfo("Configuration du pare-feu", f"Le pare-feu {selected_option} va être configuré.")

    def check_firewall_status(self):
        if platform.system() == "Windows":
            output = subprocess.check_output(["netsh", "advfirewall", "show", "allprofiles", "state"])
            firewall_status = output.decode("latin-1").strip()
        elif platform.system() == "Linux":
            output = subprocess.check_output(["iptables", "-L"])
            firewall_status = output.decode("latin-1").strip()
        else:
            firewall_status = "Impossible de vérifier le pare-feu pour ce système d'exploitation."
        messagebox.showinfo("État du pare-feu", firewall_status)

    def check_password_strength(self):
        password = self.entry_password_security.get()
        policy = PasswordPolicy.from_names(
            length=8,  # Longueur minimale
            uppercase=1,  # Au moins une lettre majuscule
            numbers=1,  # Au moins un chiffre
            special=1,  # Au moins un caractère spécial
        )
        strength = policy.test(password)
        messagebox.showinfo("Force du mot de passe", f"Force du mot de passe : {strength}")

    def check_vulnerabilities(self):
        self.detect_outdated_software()
        self.detect_system_processes()

    def detect_outdated_software(self):
        outdated_software = []

        try:
            wmic_output = subprocess.check_output(["wmic", "product", "get", "name,version"]).decode("utf-8")

            for line in wmic_output.splitlines():
                parts = line.strip().split("  ")
                if len(parts) == 2:
                    name, version = parts
                    if version.startswith("10."):
                        outdated_software.append((name, version))
        except subprocess.CalledProcessError:
            pass

        if outdated_software:
            messagebox.showinfo("Logiciels obsolètes", "Les logiciels suivants sont obsolètes sur le système :\n" +
                                "\n".join([f"{name} ({version})" for name, version in outdated_software]))
        else:
            messagebox.showinfo("Logiciels obsolètes", "Aucun logiciel obsolète détecté sur le système.")

    def detect_system_processes(self):
        system_processes = []
        for process in psutil.process_iter(['pid', 'name']):
            if process.info['pid'] <= 10:
                system_processes.append(process.info['name'])
        messagebox.showinfo("Processus système", f"Les processus système en cours d'exécution sont : {', '.join(system_processes)}")

    def show_system_info(self):
        system_info = (
            f"Système d'exploitation : {platform.system()} {platform.release()}\n"
            f"Processeur : {platform.processor()}\n"
            f"Nom de l'hôte : {socket.gethostname()}\n"
            f"Adresse IP : {socket.gethostbyname(socket.gethostname())}\n"
            f"Architecture : {platform.architecture()[0]}"
        )
        messagebox.showinfo("Informations système", system_info)

def main():
    root = tk.Tk()
    app = Application(root) 
    root.mainloop()

if __name__ == "__main__":
    main()
