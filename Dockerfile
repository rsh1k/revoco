# The enforcer sits in the request path of every tool call, so the image is
# built for the two things that actually matter there: how fast it starts and
# how little of it there is to attack.
#
# The final stage is `scratch`. There is no shell, no package manager and no
# libc — a compromised agent that somehow reached this container finds one
# static binary and nothing to pivot with. It also means the image is the size
# of the binary, which is what makes a per-pod sidecar reasonable to run at all.

FROM golang:1.24-alpine AS build
WORKDIR /src

# Dependencies first so a code change does not invalidate the module cache.
# There are no third-party dependencies today; keeping the step means adding one
# later does not silently make every build slow.
COPY go.mod ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# CGO off gives a genuinely static binary, which is what `scratch` requires.
# -trimpath keeps build-host paths out of the artifact so the build is
# reproducible; -s -w drop the symbol and DWARF tables.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/recoup-enforcer ./cmd/recoup-enforcer

# Verify the binary really is static before it reaches an image with no loader.
# Finding out at runtime means finding out in a CrashLoopBackOff.
#
# Checked by exit code rather than by matching ldd's message, because the message
# is not portable: glibc says "not a dynamic executable" and musl says "Not a
# valid dynamic program". The first version of this grepped for the glibc wording
# and so failed the build on Alpine against a binary that was perfectly static —
# a guard that fires on correct input is worse than none, because the first fix
# anyone reaches for is deleting it.
#
# ldd exits non-zero for a static binary under both libcs, which is the actual
# signal.
RUN if ldd /out/recoup-enforcer >/dev/null 2>&1; then \
      echo "binary is dynamically linked; it will not run on scratch" >&2; \
      ldd /out/recoup-enforcer >&2; exit 1; fi

FROM scratch
COPY --from=build /out/recoup-enforcer /recoup-enforcer

# Numeric, because scratch has no /etc/passwd to resolve a name against.
USER 65532:65532

EXPOSE 842
ENTRYPOINT ["/recoup-enforcer"]

# Shadow by default, matching the binary. A container that silently enforced
# when the operator expected observation would be the worst possible surprise.
CMD ["--mode", "shadow", "--bundle", "/etc/recoup/bundle.json"]
