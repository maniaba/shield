FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils \
    && mkdir /var/lib/shield-ldap

COPY slapd.conf entries.ldif /etc/shield-ldap/

EXPOSE 1389 1636

HEALTHCHECK --interval=1s --timeout=2s --retries=10 \
    CMD LDAPTLS_CACERT=/tls/ca.pem LDAPTLS_REQCERT=demand LDAPTLS_REQSAN=demand ldapwhoami -x -H ldaps://127.0.0.1:1636

CMD ["sh", "-ec", "slapadd -f /etc/shield-ldap/slapd.conf -l /etc/shield-ldap/entries.ldif && exec slapd -f /etc/shield-ldap/slapd.conf -d 0 -h 'ldap://0.0.0.0:1389/ ldaps://0.0.0.0:1636/'"]
