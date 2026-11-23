# fakegithub

The in-process GitHub fake from `internal/github`, served on a loopback port so
that a browser can reach it.

The Playwright suite drives the real binary, and every layer below the browser
runs against that fake as a test server. A browser cannot reach a test server
that lives in another process, so connecting an App, verifying it and watching a
runner appear were tested everywhere except the page they happen on. This is the
same fake with a port.

It is a test-only program. It mints nothing, verifies no signature and answers
every App as though its credentials were perfect, which is what makes it safe to
point a browser at and useless for anything else.

## Running it

You rarely start it yourself. The `connect` Playwright project starts it through
`web/tests/support/serve-connect.mjs` (`go run ./test/fakegithub`) and reads the
line it prints:

```text
fakegithub url=http://127.0.0.1:PORT app_id=N installation_id=N
```

### Queueing a job

Pass `-control` and it also serves a control route on a second loopback port,
announced on one more line:

```text
fakegithub control=http://127.0.0.1:PORT
```

`POST /jobs` with a JSON body queues a job on the fake, so a harness driving the
real binary can make work appear:

```sh
curl -s -X POST http://127.0.0.1:PORT/jobs \
  -d '{"repo":"acme/widgets","workflow":"ci","job":"build","labels":["self-hosted"]}'
```

`repo`, `workflow` and `job` are required; the answer is the queued job. Without
the flag nothing changes: no second port and no second line.

To look at it by hand, run `go run ./test/fakegithub`, give an installation that
URL, and stop it with Ctrl-C. It serves three repositories (`acme/widgets`,
`acme/site`, `acme/infra`), the same names the demo seed uses.
