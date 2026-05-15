import subprocess, platform
from .logger import get_logger

log = get_logger("Launcher")

COMMAND_TEMPLATES = {
    "nmap_quick": "nmap -T4 -F {target}",
    "nmap_full": "nmap -sV -sC -p- {target}",
    "ffuf": "ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
    "sqlmap": "sqlmap -u https://{target} --batch --banner",
    "whois": "whois {target}",
    "dig": "dig any {target} +short",
    "curl_head": "curl -I https://{target}"
}

def launch_terminal(action_key: str, target: str):
    template = COMMAND_TEMPLATES.get(action_key, "{target}")
    full_cmd = template.format(target=target)

    if platform.system() == 'Windows':
        cmd_str = f"echo SUGGESTED COMMAND: & echo {full_cmd} & echo. & echo {full_cmd}"
        try:
            subprocess.Popen(["cmd", "/c", f"start cmd /k \"{cmd_str}\""], shell=True)
            return True
        except Exception as e:
            log.error(f"Failed to launch command prompt: {e}")
    elif platform.system() == 'Darwin':
        cmd_str = f"echo SUGGESTED COMMAND:; echo {full_cmd}"
        script = f'tell application "Terminal" to do script "{cmd_str}"'
        subprocess.Popen(["osascript", "-e", script])
        return True
    elif platform.system() == 'Linux':
        cmd_str = f"echo 'SUGGESTED COMMAND:'; echo '{full_cmd}'; echo ''; exec bash"
        terminals = [
            ["konsole", "--noclose", "-e", "bash", "-c", cmd_str],
            ["alacritty", "-e", "bash", "-c", cmd_str],
            ["kitty", "bash", "-c", cmd_str],
            ["xfce4-terminal", "--hold", "-e", f"bash -c '{cmd_str}'"],
            ["xterm", "-hold", "-e", f"bash -c '{cmd_str}'"]
        ]

        for term in terminals:
            try:
                subprocess.Popen(term, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except FileNotFoundError:
                continue
    return False