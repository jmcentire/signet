FROM caddy:2-alpine

COPY Caddyfile /etc/caddy/Caddyfile
COPY index.html /srv/
COPY style.css /srv/
COPY claude-desktop-setup.md /srv/
COPY privacy.html /srv/

EXPOSE 8080
