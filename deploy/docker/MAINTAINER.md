# Docker image maintainer notes

Operational notes for whoever publishes the `ovalenzuela/dnsmesh-node`
image. Not relevant to operators consuming the image, which is why this
lives outside `deploy/docker/README.md` (the file pushed to the Docker
Hub page).

## Publishing the image

Pushes to `main` and pushes of `image-v*` tags trigger
`.github/workflows/publish-image.yml`, which builds multi-arch
(`linux/amd64`, `linux/arm64`) and pushes to Docker Hub.

Repo secrets required:
- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

## Tag scheme

| Trigger             | Tags pushed                                          |
|---------------------|------------------------------------------------------|
| push to `main`      | `:latest`, `:main`, `:sha-<short>`                   |
| push `image-vX.Y.Z` | `:X.Y.Z`, `:X.Y`, `:X`, `:latest`, `:sha-<short>`    |

The `latest` alias attaches to both the HEAD of `main` and the most
recent tagged release. The last-run workflow wins. Acceptable for a
single-maintainer project; revisit if multi-maintainer.

## Cutting a release

```bash
./scripts/release/set-version.sh 0.3.0
git push origin main
./scripts/release/tag.sh image 0.3.0 && git push origin image-v0.3.0
```

The image-v0.3.0 push exercises the full publish-image workflow end
to end: multi-arch build, SBOM + provenance attestations, Docker Hub
README sync via `peter-evans/dockerhub-description@v4`.

## Docker Hub repo description

`publish-image.yml` keeps the Docker Hub page in sync with
`deploy/docker/README.md`. Edit that file, push to `main`, and the
description and short summary refresh automatically.
