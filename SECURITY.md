# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Features

### TLS Encryption

The node uses TLS 1.3 by default with strong cipher suites:
- `TLS_AES_256_GCM_SHA384`
- `TLS_AES_128_GCM_SHA256`
- `TLS_CHACHA20_POLY1305_SHA256`

### TOTP Authentication

Time-based One-Time Password (TOTP) authentication adds an additional security layer:
- 6-digit codes valid for 30 seconds
- Secrets stored with 0600 permissions
- RFC 6238 compliant implementation

### Best Practices

1. **Always use TLS in production**
   ```yaml
   tls:
     enabled: true
     insecure_skip_verify: false
   ```

2. **Use valid certificates**
   - Obtain certificates from a trusted CA (Let's Encrypt, etc.)
   - Never use self-signed certificates in production

3. **Enable TOTP authentication**
   ```yaml
   auth:
     totp_enabled: true
   ```

4. **Secure secret storage**
   - Ensure `~/.config/honeybee/` has 0700 permissions
   - Regularly rotate TOTP secrets

5. **Run as non-root user**
   ```bash
   sudo useradd -r -s /bin/false honeybee
   sudo chown honeybee:honeybee /usr/local/bin/honeybee-node
   ```

6. **Network isolation**
   - Use firewall rules to restrict access
   - Deploy in isolated networks or VLANs
   - Consider using VPN tunnels

7. **Regular updates**
   - Keep dependencies up to date
   - Monitor security advisories
   - Apply patches promptly

## Reporting a Vulnerability

If you discover a security vulnerability, please email security@yourdomain.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you to resolve the issue.

## Security Audits

- Last audit: N/A
- Next scheduled audit: N/A

## Known Issues

None currently.

## Security Checklist for Deployment

- [ ] TLS enabled with valid certificates
- [ ] Certificate verification enabled
- [ ] TOTP authentication enabled
- [ ] Running as non-root user
- [ ] Firewall rules configured
- [ ] Logs monitored for anomalies
- [ ] Regular security updates scheduled
- [ ] Secrets properly secured (0600 permissions)
- [ ] Network segmentation implemented
- [ ] Incident response plan in place

