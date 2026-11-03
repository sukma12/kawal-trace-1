# Optional server-side component

This folder is an optional Kawal-Trace API and bounded response-queue add-on. Do not install it on every server by default. Install it only on a Linux host you administer when no compatible security-event feed already exists. It binds to loopback `127.0.0.1:8765`, not the public interface, and does not alter an existing Node website on port 9999, Cloudflare config, or firewall rules during installation.

Response worker exists but is OFF by default. It requires a separate response token, exact IP allowlist, reason/confirmation, UFW, and recent direct SSH-failure evidence. It is not appropriate for blocking HTTP visitors through Cloudflare; use a separately reviewed WAF integration for that.
