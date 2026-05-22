import subprocess, platform, os, shutil
import tempfile
from pathlib import Path

from dotenv import load_dotenv
from .logger import get_logger

log = get_logger("Launcher")
load_dotenv()
DEBUG = os.getenv("DEBUG", '').lower().strip() == 'true'

nmap = "NMAP"
ffuf = "FFUF"
sqlmap = "SQLMAP"

COMMAND_TEMPLATES = {
    "nmap_quick": {
        "tool": nmap,
        "description": "Fast top-port discovery",
        "command": "nmap -T4 -F {target}",
        "command_multi": "nmap -T4 -F -iL {file_path}"
    },
    "nmap_full": {
        "tool": nmap,
        "description": "Full service enumeration",
        "command": "nmap -sV -sC -p- {target}",
        "command_multi": "nmap -sV -sC -p- -iL {file_path}"
    },
    "ffuf_dir": {
        "tool": ffuf,
        "description": "Directory fuzzing",
        "command": "ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
        "command_multi": None
    },
    "ffuf_json": {
        "tool": ffuf,
        "description": "Json payload fuzzing",
        "command": 'ffuf -u https://{target} -X POST -H "Content-Type: application/json" -d "FUZZ"',
        "command_multi": None
    },
    "sqlmap": {
        "tool": sqlmap,
        "description": "Sql injection testing",
        "command": "sqlmap -u https://{target} --batch --banner",
        "command_multi": None
    },
    "whois": {
        "tool": "WHOIS",
        "description": "Domain ownership lookup",
        "command": "whois {target}",
        "command_multi": None
    },
    "dig": {
        "tool": "DIG",
        "description": "DNS record inspection",
        "command": "dig any {target} +short",
        "command_multi": None
    },
    "curl_head": {
        "tool": "CURL",
        "description": "HTTP header inspection",
        "command": "curl -I https://{target}",
        "command_multi": None
    },
    "wafw00f": {
        "tool": "WAFW00F",
        "description": "Web Application Firewall fingerprinting",
        "command": "wafw00f https://{target}",
        "command_multi": "wafw00f -i {file_path}"
    },
    "searchploit": {
        "tool": "SEARCHPLOIT",
        "description": "Exploit database local search",
        "command": "searchsploit {target}",
        "command_multi": None
    },
    "nikto": {
        "tool": "NIKTO",
        "description": "Web server vulnerability scanning",
        "command": "nikto -h https://{target}",
        "command_multi": "nikto -h {file_path}"
    },
    "nuclei_single": {
        "tool": "NUCLEI",
        "description": "Fast vulnerability template scanning",
        "command": "nuclei -u https://{target}",
        "command_multi": "nuclei -l {file_path}"
    },
    "whatweb": {
        "tool": "WHATWEB",
        "description": "Web technology fingerprinting",
        "command": "whatweb -a 3 https://{target}",
        "command_multi": "whatweb --input-file={file_path} -a 3"
    },
    "theharvester": {
        "tool": "THEHARVESTER",
        "description": "OSINT email, names, subdomains gathering",
        "command": "theHarvester -d {target} -b all",
        "command_multi": None
    }
}

def launch_terminal(action_key: str, target: str, custom_cmd: str = None):
    system = platform.system()
    if custom_cmd:
        full_cmd = custom_cmd
    else:
        template = COMMAND_TEMPLATES.get(action_key, "{target}")
        if not template and not custom_cmd:
            return False
        full_cmd = template['command'].format(target=target)

    if _launch_by_system(full_cmd, system):
        return True
    else:
        log.error(f"Unsupported platform: {system}")
        return False

def launch_terminal_multi(action_key: str, targets: list[str], custom_cmd: str = None) -> bool:
    from utils import schedule_cleanup

    template = COMMAND_TEMPLATES.get(action_key)
    system = platform.system()

    if not template and not custom_cmd:
        log.error(f"No template found for action: {action_key}")
        return False

    has_bulk_cmd = template and template.get('command_multi')

    if not custom_cmd and has_bulk_cmd:
        fd, tmp_file = tempfile.mkstemp(
            prefix='subv_targets_',
            suffix='.txt'
        )
        os.close(fd)

        file_path = Path(tmp_file)
        try:
            file_path.write_text("\n".join(targets))
            bulk_cmd = template['command_multi'].format(
                file_path=str(file_path)
            )

            ok = _launch_by_system(bulk_cmd, system)

            if ok:
                schedule_cleanup(str(file_path), delay=300)
                return True
            else:
                schedule_cleanup(str(file_path), delay=1)
                return False

        except Exception as e:
            log.error(f"Failed to launch terminal multi action: {e}")
            schedule_cleanup(str(file_path), delay=1)
            return False

    if custom_cmd:
        try:
            full_cmd = custom_cmd
            ok = _launch_by_system(full_cmd, system)
            return ok

        except Exception as e:
            log.error(f"Failed to launch bulk command: {e}")
            return False

    log.error(f"Action '{action_key}' tidak support bulk mode")
    return False

def _launch_windows(cmd: str) -> bool:
    full_command = f'start "Subv Execution" cmd /k "{cmd}"'
    try:
        subprocess.Popen(
            full_command,
            shell=True)
        return True
    except Exception as e:
        log.error(f"Windows launch Failed: {e}")
        return False

def _launch_macos(cmd: str) -> bool:
    try:
        script = f'tell application "Terminal" to do script "{cmd}"'
        subprocess.Popen(["osascript", "-e", script])
        return True
    except Exception as e:
        log.error(f"macOs launch failed: {e}")
        return False

def _launch_linux(cmd: str) -> bool:
    shell = "fish" if shutil.which("fish") else "bash"
    terminals = [
        ["alacritty", "-e", shell, "-c", f"{cmd}; read"],
        ["konsole", "--noclose", "-e", shell, "-c", cmd],
        ["kitty", shell, "-c", f"{cmd}; read"],
        ["wezterm", "start", "--", shell, "-c", f"{cmd}; read"],
        ["terminator", "-e", f"{shell} -c '{cmd}; read'"],
        ["xfce4-terminal", "--hold", "-e", f"{shell} -c '{cmd}'"],
        ["xterm", "-hold", "-e", f"{shell} -c '{cmd}'"],
        ["st", "-e", shell, "-c", f"{cmd}; read"],
        ["foot", shell, "-c", f"{cmd}; read"],
        ["gnome-terminal", "--", shell, "-c", f"{cmd}; read"],
        ["qterminal", "-e", f"{shell} -c '{cmd}; read'"],
    ]

    for term in terminals:
        try:
            subprocess.Popen(
                term,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if DEBUG:
                log.debug(f"Launched with {term[0]}")
            return True
        except FileNotFoundError:
            continue
        except Exception as e:
            log.error(f"Failed with {term[0]}: {e}")
            continue
    return False

def _launch_by_system(cmd: str, system: str) -> bool:
    if system == 'Windows':
        return _launch_windows(cmd)
    elif system == 'Darwin':
        return _launch_macos(cmd)
    elif system == 'Linux':
        return _launch_linux(cmd)
    return False