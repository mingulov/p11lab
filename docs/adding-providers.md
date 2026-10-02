# Adding providers

Use a recipe and metadata with the shared catalogue, runtime and evidence
contracts. Keep build tools, checker datasets, tracing and optional integrations
out of the basic runtime unless the provider requires them. A remote native
library needs its compatible client module and transport; a shared network alone
does not let another application load it.

Record exact upstream revision/archive hash, ordered patches and licenses,
base/package inputs, original notices, linked/static closure, modifications and
build/install instructions. Exercise the real resulting artifact and collect its
actual-content inventory with the operations in [licensing.md](licensing.md).
Provider packaging does not normalize native errors or introduce silent retries.
A declared patch that fails to apply fails the build. Copied source grants remain
with the source; P11Lab's root license does not repair missing upstream rights.

RustSSM and softKMS have a scoped fresh-qualification route (D1): develop new
reviewed packaging, inventory the resulting new artifact and establish exact
source/notice/delivery evidence. Existing reference recipes, local-only
restrictions and old binaries retain their disposition. This route does not
retroactively approve them. The inherited RustSSM discovery/provisioning patch
retains its MIT grant, provenance and original notice; do not blanket-relicense
it as Apache or silently treat it as a PKCS#11 semantic fix. Qualification remains
artifact-specific and does not authorize building or publishing either provider.

Optional debug companions are binary outputs with their own digest, exact parent,
matching debug-file/build-ID relationship and source-first admission. They cannot
be placed into a source-only companion. Any new notice layer changes the runtime
identity and requires rebinding its source/SPDX/admission and debug companion,
even if provider ELF hashes remain unchanged. Checker/proxy/data derivatives and
builder/cache exports likewise need their own actual-content admission.
