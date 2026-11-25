"""Local MQTT broker credentials template.

Copy this file to `mqtt_secrets.py` (which is gitignored) and fill in your broker settings.
Environment variables in connect_vr921.py override these values.
"""

# Broker connection
HA_MQTT_HOST = ""  # e.g. "192.168.1.10"
HA_MQTT_PORT = 1883

# Auth (leave empty for anonymous)
HA_MQTT_USER = ""  # your user
HA_MQTT_PASSWORD = ""  # your password
