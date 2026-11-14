# Stand deployment

Reproducible scripts and evidence for the authorized lab are added in P07.
The target topology and TLS/DB/agent setup are documented in
`docs/stand-setup.md`. No secret is stored in this directory; passwords are
read from `.secrets/` or from the process environment by the operator.
