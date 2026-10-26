# check=skip=InvalidDefaultArgInFrom
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The oss-verify builder: a toolchain image, pinned by digest in infra/toolchains.tsv or a lock, plus the interface a
# project's Dockerfile and build.sh are written against, in OSS-Fuzz's names ($SRC, $WORK, $OUT, $CC, $CFLAGS,
# $LIB_FUZZING_ENGINE, $SANITIZER, compile).
# docs/build-contract.md describes it.
#
# The toolchain image is a build argument with no default, so the build fails without one ("base name (${TOOLCHAIN})
# should not be blank"). tools/check passes it (--build-arg TOOLCHAIN=<image>): the image --toolchain gives, else the
# one the project's lock names, else the newest for the project's language in infra/toolchains.tsv, the one file that
# lists the toolchains (docs/build-contract.md, "Toolchains"). The parser directive on line 1 keeps BuildKit from
# warning, on every build, that the argument has no default.
ARG TOOLCHAIN
FROM ${TOOLCHAIN}

# SECURITY: the builder trusts no root of eMudhra's emSign CAs or of Comodo's AAA Certificate Services. Mozilla's
# security blog reports (2026-10-20) that private keys of intermediates under them are compromised. The toolchain
# images carry them: Alpine's store has the four emSign roots, and pip's own certifi has those and AAA. A project's
# Dockerfile runs on this image with the network, so this step disables the roots in Alpine's store (update.d then
# makes the Java store again), removes them from every certifi cacert.pem in the image, and fails the build if a store
# still holds one, or holds none at all. Alpine has no openssl command, so Python's ssl module reads the stores. The
# step changes no file that a link takes, and it runs before the COPYs, so a change to them does not run it again.
RUN python3 - <<'DISTRUST'
import os, pathlib, re, ssl, subprocess, sys

BAD = re.compile(r"emSign|eMudhra|AAA[ _]Certificate[ _]Services", re.I)

conf = pathlib.Path("/etc/ca-certificates.conf")
conf.write_text("".join(
    ("!" + l if not l.startswith(("!", "#")) and BAD.search(l) else l) + "\n"
    for l in conf.read_text().splitlines()
))
subprocess.run(["update-ca-certificates"], check=True, stdout=subprocess.DEVNULL)

bundles = []
for root, dirs, files in os.walk("/"):
    dirs[:] = sorted(d for d in dirs if os.path.join(root, d) not in ("/proc", "/sys", "/dev"))
    if os.path.basename(root) == "certifi" and "cacert.pem" in files:
        bundles.append(pathlib.Path(root, "cacert.pem"))
for pem in bundles:
    blocks = re.split(r"\n(?=\n# Issuer:)", pem.read_text())
    kept = [b for b in blocks if not any(BAD.search(h) for h in re.findall(r"^# (?:Issuer|Subject|Label):.*$", b, re.M))]
    pem.write_text("\n".join(kept))
    print(f"{pem}: removed {len(blocks) - len(kept)} roots")

def subjects(path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(path))
    return [", ".join("%s=%s" % kv for rdn in cert["subject"] for kv in rdn) for cert in context.get_ca_certs()]

stores = {str(path): subjects(path) for path in [pathlib.Path("/etc/ssl/certs/ca-certificates.crt"), *bundles]}
java = pathlib.Path("/etc/ssl/certs/java/cacerts")
if java.exists():
    listing = subprocess.run(["keytool", "-list", "-v", "-keystore", str(java), "-storepass", "changeit"],
                             check=True, capture_output=True, text=True).stdout
    stores[str(java)] = [l for l in listing.splitlines() if l.startswith("Owner:")]

failed = False
for path, subs in stores.items():
    left = [s for s in subs if BAD.search(s)]
    print(f"{path}: {len(subs)} roots")
    if not subs or left:
        print(f"FAIL: {path}: {len(subs)} roots, still trusted: {left}")
        failed = True
sys.exit(failed)
DISTRUST

COPY toolchain.sh link-fuzz-target recipes.sh release-target.sh /usr/local/lib/oss-verify/
COPY driver/ /usr/local/lib/oss-verify/driver/
COPY rust/ /usr/local/lib/oss-verify/rust/
COPY python/ /usr/local/lib/oss-verify/python/
COPY go/ /usr/local/lib/oss-verify/go/
COPY compile fetch-commit lay-out-sources /usr/local/bin/
RUN chmod 0755 /usr/local/bin/compile /usr/local/bin/fetch-commit /usr/local/bin/lay-out-sources \
               /usr/local/lib/oss-verify/link-fuzz-target /usr/local/lib/oss-verify/go/compile-go \
 && mkdir -p /src /work /out

ENV SRC=/src \
    WORK=/work \
    OUT=/out \
    SANITIZER=none
WORKDIR /src
CMD ["compile"]
