import requests
from typing import Dict, Any, Optional
from sentinel.config import AlertConfig

class AlertDispatcher:
    def __init__(self, config: AlertConfig):
        self.config = config

    def send_alert(self, title: str, message: str, severity: str = "WARNING") -> Dict[str, Any]:
        """Dispatches an alert to configured notification channels (Telegram, Discord, Slack)."""
        results = {
            "telegram": False,
            "discord": False,
            "slack": False,
            "details": []
        }

        # Telegram
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            try:
                tg_url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
                text = f"🚨 *LSP-Sentinel [{severity}]*\n*Subject:* {title}\n\n{message}"
                resp = requests.post(tg_url, json={
                    "chat_id": self.config.telegram_chat_id,
                    "text": text,
                    "parse_mode": "Markdown"
                }, timeout=5)
                results["telegram"] = resp.status_code == 200
                results["details"].append(f"Telegram: status {resp.status_code}")
            except Exception as e:
                results["details"].append(f"Telegram error: {str(e)}")

        # Discord
        if self.config.discord_webhook_url:
            try:
                color = 0xff0000 if severity in ("CRITICAL", "ERROR") else 0xffaa00
                payload = {
                    "embeds": [{
                        "title": f"🚨 LSP-Sentinel Alert: {title}",
                        "description": message,
                        "color": color,
                        "footer": {"text": "LSP-Sentinel Autonomous SRE Suite"}
                    }]
                }
                resp = requests.post(self.config.discord_webhook_url, json=payload, timeout=5)
                results["discord"] = resp.status_code in (200, 204)
                results["details"].append(f"Discord: status {resp.status_code}")
            except Exception as e:
                results["details"].append(f"Discord error: {str(e)}")

        # Slack
        if self.config.slack_webhook_url:
            try:
                payload = {
                    "text": f"*[{severity}] LSP-Sentinel:* {title}\n>{message}"
                }
                resp = requests.post(self.config.slack_webhook_url, json=payload, timeout=5)
                results["slack"] = resp.status_code == 200
                results["details"].append(f"Slack: status {resp.status_code}")
            except Exception as e:
                results["details"].append(f"Slack error: {str(e)}")

        return results
