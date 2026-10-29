# RESULTS — generated from `experiments/out/results.csv`

JDK: 25.0.5+8-LTS  
OS: Linux 7.2.11-arch1-1  
Trials per memory cell: 2

Every memory trial carries a positive control (unwiped canary) and a negative control. An INVALID trial is not a pass. `NOT_CHECKABLE` is not a pass.

## Memory matrix

| collector | mode | valid | target FOUND (false assurance) | rate | Wilson 95% CI | positive control FOUND |
|---|---|---|---|---|---|---|
| G1 | HOT | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| G1 | MOVE | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| G1 | WIPE | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| Parallel | HOT | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| Parallel | MOVE | 2 | 2 | 1.000 | [0.342, 1.000] | 1.000 |
| Parallel | WIPE | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| Serial | HOT | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| Serial | MOVE | 2 | 2 | 1.000 | [0.342, 1.000] | 1.000 |
| Serial | WIPE | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| Shenandoah | HOT | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| Shenandoah | MOVE | 2 | 2 | 1.000 | [0.342, 1.000] | 1.000 |
| Shenandoah | WIPE | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| ZGC | HOT | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| ZGC | MOVE | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |
| ZGC | WIPE | 2 | 0 | 0.000 | [0.000, 0.658] | 1.000 |

## File matrix

| method | trials | logical result | note |
|---|---|---|---|
| crypto | 2 | 2/2 | raw-media residue NOT_CHECKABLE without an image |
| delete-only | 2 | 2/2 | raw-media residue NOT_CHECKABLE without an image |
| overwrite | 2 | 2/2 | raw-media residue NOT_CHECKABLE without an image |

## Tamper matrix

| mutation | trials | detected | rate |
|---|---|---|---|
| backdate | 2 | 2 | 1.000 |
| delete | 2 | 2 | 1.000 |
| edit | 2 | 2 | 1.000 |
| fork | 2 | 2 | 1.000 |

## Overhead

| method | size | median ms |
|---|---|---|
| overwrite | 1MiB | median of 5; p95=0 |
| crypto | 1MiB | median of 5; p95=20 |
| overwrite | 16MiB | median of 5; p95=6 |
| crypto | 16MiB | median of 5; p95=237 |
| overwrite | 64MiB | median of 5; p95=19 |
| crypto | 64MiB | median of 5; p95=84 |

## Limits

User-space Java cannot verify the SSD flash translation layer, bad-block pools, controller-held copies, journal copies, snapshots, or backups. These are logical-level results. The witness is a local key, not an independent party. No result here is a physical-erasure guarantee.
