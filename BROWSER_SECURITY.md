# Browser request boundary

Run the UI from the Python server itself. The shipped HTML loads
`browser-session.js`, which obtains a session cookie and CSRF token and attaches the
token to every same-origin mutation. API clients must GET `/browser-session`, retain
the cookie, then send `Origin: http://127.0.0.1:<server-port>`, the returned
`X-CSRF-Token`, and `Content-Type: application/json` for POST/PATCH/DELETE requests.
Tokens expire after 12 hours and on server restart; the client refreshes the session before each action.
Never blindly retry a mutation. Logout uses POST.

The boundary checks Host including the actual listening port, Origin, Fetch Metadata,
duplicate security headers, and tokens before dispatch. JSON is the only supported
mutation format; multipart and WebSocket upgrades are rejected. No forwarded headers
are trusted. CORS does not grant other local ports access. Serve built or legacy UI
through the backend, rather than accessing the API from a separate development origin.

Flashcards can explicitly allow HTTPS authorities via
comma-separated `APP_TRUSTED_ORIGINS=https://your-host.example` only with `APP_PASSCODE`
set; the existing passcode authentication still gates protected routes. A TLS proxy
must preserve the configured Host. Forwarded/X-Forwarded-* headers are ignored for
these explicit HTTPS authorities; they never establish authority, authentication,
or the expected Origin. They are rejected for local Host values. This supports
Tailscale Serve without trusting its forwarded metadata. Keep the backend bound to
`127.0.0.1` and set `APP_COOKIE_SECURE=1`. Neither a remote bind nor trusted-origin configuration alone
grants authenticated access. Do not expose a plain HTTP remote service.

Validation: `python -m unittest discover -s tests -p test_browser_boundary.py` runs real
HTTP requests against the actual route handler, stubbing only provider/disk mutations.
It proves rejected requests never dispatch and valid sessions dispatch once; it does
not claim live provider ingestion or deployed proxy validation.
