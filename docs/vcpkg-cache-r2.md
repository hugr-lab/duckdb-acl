# The vcpkg binary cache, on Cloudflare R2

Building the Flight SQL door means building Arrow and gRPC — 89 vcpkg ports, measured at 11m26s on a
laptop and about 98 minutes on a CI runner from cold. A binary cache is what turns that into minutes:
`airport`, which links the same libraries, builds its whole platform matrix in **21 minutes** because
its packages come out of a bucket instead of a compiler.

## Why R2 rather than S3

The cost here is **egress**, not storage. Six platform jobs pulling a couple of gigabytes each, several
runs a day, is 100–300 GB a month.

| | storage | egress | our monthly bill |
| --- | --- | --- | --- |
| **Cloudflare R2** | $0.015/GB (10 GB free) | **free** | $0 – a few cents |
| Backblaze B2 | $0.006/GB | free to 3× storage, then $0.01/GB | cents |
| AWS S3 | $0.023/GB | $0.09/GB | ~$20 |

Our packages should come to 10–15 GB across six triplets, so R2's free tier very nearly covers it.

## What to create, once

1. **A bucket.** Cloudflare dashboard → R2 → *Create bucket*. Name it `duckdb-acl-vcpkg-cache`,
   location *Automatic*. Nothing else to configure — no public access, no custom domain.

2. **An API token.** R2 → *Manage API tokens* → *Create API token*:
   - permission **Object Read & Write**,
   - scoped to that one bucket,
   - no TTL.

   It gives you an **Access Key ID** and a **Secret Access Key**. The secret is shown once.

3. **Your account id**, from the R2 page. The endpoint is `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`.

## What to put in the repository

Four secrets and one variable. From a terminal, with the values from above:

```sh
gh secret set VCPKG_CACHING_AWS_ACCESS_KEY_ID       --body '<access key id>'
gh secret set VCPKG_CACHING_AWS_SECRET_ACCESS_KEY   --body '<secret access key>'
gh secret set VCPKG_CACHING_AWS_ENDPOINT_URL        --body 'https://<ACCOUNT_ID>.r2.cloudflarestorage.com'
gh secret set VCPKG_CACHING_AWS_DEFAULT_REGION      --body 'auto'

gh variable set VCPKG_BINARY_SOURCES --body 'clear;x-aws,s3://duckdb-acl-vcpkg-cache/,readwrite'
```

The names are not ours to choose: `duckdb/extension-ci-tools/.github/workflows/_extension_distribution.yml`
reads exactly these and passes them to the AWS CLI as `AWS_*`. `auto` is R2's only region.

## What happens without them

Nothing breaks. With `vcpkg_binary_sources` unset the reusable workflow falls back to
`clear;http,https://vcpkg-cache.duckdb.org,read` — duckdb's own public cache, read-only. Builds still
work; they are only slow when it does not happen to hold what we need, and nothing we build is kept.

The same fallback covers pull requests **from forks**, which never see repository secrets. That is the
right failure mode: a fork's build is slower, not broken, and it cannot write to our bucket.

## The first run is still slow

The cache starts empty, so the first run of each platform pays full price and fills it. Merge to the
default branch first if you want the cache warm before anyone's pull request needs it.

## Where it is used

`.github/workflows/distribution.yml` — the build community-extensions will run, run here first. It
calls their reusable workflow with these credentials, so the cache is shared by every platform job and
by every run on any branch.

It replaced a hand-rolled release matrix that had accumulated three bugs the reusable workflow does not
have: WASM jobs configured with Ninja and then built with `emmake make`, a Windows job with no vcpkg at
all, and the wrong CRT triplet. That is the argument for calling their workflow rather than imitating
it — the imitation is where the bugs live.
