# syntax=docker/dockerfile:1
FROM scratch AS source
COPY <<'MESSAGE' /message
hello from a quoted heredoc
MESSAGE

FROM scratch
RUN --mount=type=cache,target=/tmp <<SCRIPT
echo "building ${TARGET:-default}"
SCRIPT
COPY --link --from=source /message /message
CMD ["/message"]
