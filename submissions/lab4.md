# Lab 4 Submission — SBOM and SCA

## Task 1

### SBOM counts

| File | Format | Count |
|---|---|---:|
| `labs/lab4/juice-shop.cdx.json` | CycloneDX components | 3068 |
| `labs/lab4/juice-shop.spdx.json` | SPDX packages | 909 |

CycloneDX `specVersion`:

```text
1.7
```

CycloneDX and SPDX count different object models. CycloneDX lists more fine-grained components from the image, while SPDX groups software as packages and focuses more on license/compliance metadata. This is why one image gives different counts in two valid SBOM formats.

### Grype severity table

| Severity | Count |
|---|---:|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| **Total** | **183** |

### Top ten findings

| # | Severity | ID | Package | Fix |
|---:|---|---|---|---|
| 1 | Critical | `GHSA-c7hr-j4mj-j2w6` | `jsonwebtoken@0.1.0` | `4.2.2` |
| 2 | Critical | `GHSA-c7hr-j4mj-j2w6` | `jsonwebtoken@0.4.0` | `4.2.2` |
| 3 | Critical | `GHSA-jf85-cpcp-j695` | `lodash@2.4.2` | `4.17.12` |
| 4 | Critical | `CVE-2026-63073` | `libssl3t64@3.5.5-1~deb13u2` | `3.5.7-1~deb13u2` |
| 5 | Critical | `GHSA-mp2f-45pm-3cg9` | `decompress@4.2.1` | none |
| 6 | Critical | `GHSA-xwcq-pm8m-c4vf` | `crypto-js@3.3.0` | `4.2.0` |
| 7 | Critical | `CVE-2026-34182` | `libssl3t64@3.5.5-1~deb13u2` | `3.5.6-1~deb13u2` |
| 8 | Critical | `GHSA-23hp-3jrh-7fpw` | `tar@4.4.19` | `7.5.19` |
| 9 | Critical | `GHSA-23hp-3jrh-7fpw` | `tar@6.2.1` | `7.5.19` |
| 10 | Critical | `GHSA-23hp-3jrh-7fpw` | `tar@7.5.15` | `7.5.19` |

Nine of the top ten findings have a fix version. I would patch the fixable Critical findings first, especially `jsonwebtoken`, `lodash`, `libssl3t64`, `crypto-js`, and `tar`. For `decompress`, there is no fix in the output, so I would check if it can be removed, replaced, or isolated.

## Task 2

### Grype and Trivy comparison

| Severity | Grype | Trivy | Delta |
|---|---:|---:|---:|
| Critical | 14 | 10 | +4 |
| High | 85 | 64 | +21 |
| Medium | 65 | 68 | -3 |
| Low | 12 | 31 | -19 |
| Negligible | 7 | 0 | +7 |
| **Total** | **183** | **173** | **+10** |

### Different identifiers

| Tool | ID | Package | Explanation |
|---|---|---|---|
| Grype only | `CVE-2026-48617` | `node@24.15.0` | Grype matched the Node binary from the SBOM. Trivy did not report this identifier, probably because of different binary matching or advisory source coverage. |
| Trivy only | `CVE-2015-9235` | `jsonwebtoken@0.1.0`, `jsonwebtoken@0.4.0` | Trivy reported the CVE identifier. Grype reported the related GitHub advisory `GHSA-c7hr-j4mj-j2w6`, so this is mainly different advisory naming and mapping. |

The decoupled SBOM approach is worth it when the same inventory must be reused later. For example, Lab 8 signs the CycloneDX SBOM as an attestation, so the SBOM becomes evidence connected to the image digest. It also lets us rescan the same shipped inventory later when new vulnerabilities are published. A single scanner like Trivy is better for quick local checks because it is one command and has fewer moving parts.

## Bonus

### Attestation command

```bash
IMAGE='bkimminich/juice-shop:v20.0.0'
REPO_DIGEST=$(docker inspect "$IMAGE" --format '{{index .RepoDigests 0}}')
DIGEST=${REPO_DIGEST#*@sha256:}
jq -n --arg image "$IMAGE" --arg digest "$DIGEST" --slurpfile predicate labs/lab4/juice-shop.cdx.json \
  '{"_type":"https://in-toto.io/Statement/v0.1", subject:[{name:$image, digest:{sha256:$digest}}], predicateType:"https://cyclonedx.org/bom", predicate:$predicate[0]}' \
  > labs/lab4/juice-shop-attestation.json
```

First 20 lines:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:d0c3bc8c-59cd-404e-ac13-dd325a975583",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-20T15:16:29+03:00",
      "tools": {
```

Digest:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

The attestation uses the digest because a tag can move to another image, but the digest identifies exact image content. This file claims that the CycloneDX SBOM is the predicate for the Juice Shop image with this digest. A verifier or deployment pipeline would check this attestation before trusting the SBOM. It does not prove that the image is safe or vulnerability-free; it only connects this SBOM statement to this exact image digest.
