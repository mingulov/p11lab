# Native application example

Install a verified Debian 13 amd64 SoftHSM candidate using the [native guide](../../docs/native.md).
Set `PREFIX`, `STATE` and `CONTROL` to explicit separate directories. Set
`P11LAB_PIN_FILE` and `P11LAB_SO_PIN_FILE` to existing private credential files
without final newlines; never echo credentials. Invoke:

```sh
./run.sh /path/to/application 'literal argument'
```

Your application receives absolute `P11LAB_MODULE` and `SOFTHSM2_CONF` paths.
The example preserves compatible existing state and fails on partial state.
It uses the installed shell adapter directly and needs no Python or checker.
Use separate state for independent clients; reuse does not relocate token state.
