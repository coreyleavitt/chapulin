# chapulin toolchain image.
#
# The base ships nim 2.2.10, nimble, git and a C toolchain, multi-platform
# (linux/amd64 + windows/amd64) — so this builds and runs on a Linux daemon
# (CI / the interop compose stack) and a Windows daemon alike.
#
# Dependencies are resolved on the HOST by milpa, not in the image: run
# `milpa fetch` first (see scripts/dev-test.ps1) — it writes nim.cfg + _deps/
# into the project tree, which docker-compose bind-mounts at /app (or C:\app on
# Windows). The container only needs the compiler; nim reads the generated
# nim.cfg for every --path. This is why there is no `nimble install` step.
FROM ghcr.io/coreyleavitt/nim:2.2.10

WORKDIR /app

# Default: run the unit + property suite the same way scripts/dev-test.ps1 does.
# (Requires the host to have run `milpa fetch` so nim.cfg + _deps/ are present.)
CMD ["nim", "c", "-r", "--hints:off", "tests/t_props.nim"]
