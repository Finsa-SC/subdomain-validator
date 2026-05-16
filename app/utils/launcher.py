import subprocess, platform, os, shutil
import tempfile

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
        "command": "ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt"
    },
    "ffuf_json": {
        "tool": ffuf,
        "description": "Json payload fuzzing",
        "command": "ffuf -u https://{target} -X POST -H 'Content-Type: application/json' -d 'FUZZ'"
    },
    "sqlmap": {
        "tool": sqlmap,
        "description": "Sql injection testing",
        "command": "sqlmap -u https://{target} --batch --banner"
    },
    "whois": {
        "tool": "WHOIS",
        "description": "Domain ownership lookup",
        "command": "whois {target}"},
    "dig": {
        "tool": "DIG",
        "description": "DNS record inspection",
        "command": "dig any {target} +short"
    },
    "curl_head": {
        "tool": "CURL",
        "description": "HTTP header inspection",
        "command": "curl -I https://{target}"
    },
    "wafw00w": {
        "tool": "WAFW00F",
        "description": "Web Application Firewall fingerprinting",
        "command": "wafw00f https://{target}",
        "command_multi": "wafw00f -i {file_path}"
    },
    "searchploit": {
        "tool": "SEARCHPLOIT",
        "description": "Exploit database local search",
        "command": "searchploit {target}"
    },
    "nicto": {
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
        "description": "Next-gen web scanner technology identifier",
        "command": "whatweb -a 3 https://{target}",
        "command_multi": "whatweb --input-file={file_path} -a 3"
    },
    "theharvester": {
        "tool": "THEHARVESTER",
        "description": "OSINT email, names, subdomains gathering",
        "command": "theHarvester -d {target} -b all"
    }
}

def launch_terminal(action_key: str, target: str, custom_cmd: str = None):
    system = platform.system()
    if custom_cmd:
        full_cmd = custom_cmd
    else:
        template = COMMAND_TEMPLATES.get(action_key, "{target}")
        full_cmd = template['command'].format(target=target)

    if system == 'Windows':
        return _launch_windows(full_cmd)
    elif system == 'Darwin':
        return _launch_macos(full_cmd)
    elif system == 'Linux':
        return _launch_linux(full_cmd)
    else:
        log.error(f"Unsupported platform: {system}")
        return False

def launch_terminal_multi(action_key: str, targets: list[str], custom_cmd: str = None) -> tuple[int, int]:
    template = COMMAND_TEMPLATES.get(action_key)
    system = platform.system()
    success, fail = 0, 0

    if not custom_cmd:
        fd, tmp_file = tempfile.mkstemp(suffix='.txt', prefix='subv_targets_')
        try:
            with os.fdopen(fd, 'w') as file:
                file.write("\n".join(targets))
            bulk_cmd = COMMAND_TEMPLATES[action_key].format(file=tmp_file)

            if system == 'Windows':
                ok = _launch_windows(bulk_cmd)
            elif system == 'Darwin':
                ok = _launch_macos(bulk_cmd)
            elif system == 'Linux':
                ok = _launch_linux(bulk_cmd)
            else:
                ok = False

            return (1, 0) if ok else (0, 1)
        except Exception as e:
            log.error(f"Failed to launch terminal multi action: {e}")
            return 0, 1
    for target in targets:
        if custom_cmd:
            full_cmd = custom_cmd.replace("{target}", target)
        else:
            full_cmd = template['comman_multi'].format(target=target)

        if system == "Windows":
            ok = _launch_windows(full_cmd)
        elif system == "Darwin":
            ok = _launch_macos(full_cmd)
        else:
            ok = _launch_linux(full_cmd)

        if ok:
            success += 1
        else:
            fail += 1

    return success, fail


def _launch_windows(cmd: str) -> bool:
    try:
        subprocess.Popen(
            ["cmd", "/k", cmd],
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