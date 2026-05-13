# HTTP probing via redirect/state query parameters (regex)
# Based on CrowdSec http-probing scenario, narrowed to abuse of
# OAuth2 / SSO redirect parameters as a vector for path probing.
#
# Typical hostile request:
#   /oauth2/authorize?...&state=NONCE%3A%2Fphpinfo.php
#   /auth/callback?...&redirect_uri=https%3A%2F%2Fhost%2F.env
#
# Patterns match the RAW (URL-encoded) REQUEST_URI as sent by the client.

# OAuth2-proxy "state=NONCE:/<path>" path-injection probe
[?&]state=[^&]*(%3[Aa]%2[Ff]|%3[Aa]/|:%2[Ff]|:/)(phpinfo|wp-(login|admin|config)|adminer|phpmyadmin|server-(status|info)|\.env|\.git|\.aws|\.ssh|\.htaccess|\.htpasswd|web\.config)

# Same probe via any common redirect-style parameter
[?&](redirect|redirect_uri|return|return_url|returnurl|return_to|url|next|continue|goto|dest|destination|callback|rd)=[^&]*(%3[Aa]%2[Ff]|%3[Aa]/|:%2[Ff]|:/)[^&]*(phpinfo|wp-(login|admin|config)|adminer|phpmyadmin|server-(status|info)|\.env|\.git|\.aws|\.ssh|\.htaccess|\.htpasswd|web\.config)

# Sensitive file extension as final segment of a redirect-style value
[?&](redirect|redirect_uri|return|return_url|returnurl|return_to|url|next|continue|goto|dest|destination|state|callback|rd)=[^&]*\.(env|git|aws|ssh|sql|sqlite|bak|swp|key|pem|p12|pfx)($|&|%26)

# Path traversal embedded in any redirect-style parameter value
[?&](redirect|redirect_uri|return|return_url|returnurl|return_to|url|next|continue|goto|dest|destination|state|callback|rd)=[^&]*(%2[Ee]%2[Ee]%2[Ff]|%2[Ee]%2[Ee]/|\.\.%2[Ff]|\.\./)
