import subprocess, platform, os

from dotenv import load_dotenv

from .logger import get_logger

log = get_logger("Launcher")
load_dotenv()
DEBUG = os.getenv("DEBUG", '').lower().strip() == 'true'

COMMAND_TEMPLATES = {
    "nmap_quick": "nmap -T4 -F {target}",
    "nmap_full": "nmap -sV -sC -p- {target}",
    "ffuf_dir": "ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
    "ffuf_json": "ffuf -u https://{target} -X POST -H 'Content-Type: application/json' -d 'FUZZ'",
    "sqlmap": "sqlmap -u https://{target} --batch --banner",
    "whois": "whois {target}",
    "dig": "dig any {target} +short",
    "curl_head": "curl -I https://{target}"
}

def launch_terminal(action_key: str, target: str):
    template = COMMAND_TEMPLATES.get(action_key, "{target}")
    full_cmd = template.format(target=target)

    if platform.system() == 'Windows':
        _launch_windows(full_cmd)
    elif platform.system() == 'Darwin':
        _launch_macos(full_cmd)
    elif platform.system() == 'Linux':
        _launch_linux(full_cmd)
    return False

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
    terminals = [
        ["konsole", "--noclose", "-e", "bash", "-c", cmd],
        ["alacritty", "-e", "bash", "-c", cmd],
        ["kitty", "bash", "-c", cmd],
        ["xfce4-terminal", "--hold", "-e", f"bash -c '{cmd}'"],
        ["xterm", "-hold", "-e", f"bash -c '{cmd}'"]
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