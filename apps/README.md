# apps/

Standalone web applications built in this repo. Each app owns its own
`package.json`, build config and tests; nothing here depends on the Python `rex`
package, and `rex` does not depend on them.

| App | What it is | Live |
| --- | --- | --- |
| [`cinematheque/`](cinematheque/README.md) | Local-first personal media library (React + Vite + TypeScript PWA). Import your own video files, parse them, play them — entirely on-device. | <https://cinematheque-chi.vercel.app> |

## Deploying an app

`cinematheque` is deployed to Vercel as a static Vite build. Because this
repository is a monorepo, the Vercel project **must** set its root directory to
the app folder:

| Setting | Value |
| --- | --- |
| Framework preset | Vite |
| Root directory | `apps/cinematheque` |
| Build command | `npm run build` (default) |
| Output directory | `dist` (default) |
| Install command | `npm install` (default) |

There are no environment variables and no server-side code, so a deployment is
fully static.

**Protection gotcha:** a team can have *Deployment Protection* on, in which case
per-deployment and git-branch URLs require a Vercel login. The project's stable
production alias (`<project>-<team>.vercel.app` / custom alias) is what you share
publicly.
