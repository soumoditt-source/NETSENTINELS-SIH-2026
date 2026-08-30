# Security policy

Report security issues privately to the project maintainers. Do not attach
malware, credentials, bot tokens, webhooks, or live network captures containing
sensitive data.

The application is read-only by design. Runtime does not download datasets or
models. Uploaded PCAPs are processed offline, filenames are constrained, and
Python model artifacts require repository containment plus SHA-256 validation
before deserialization.
