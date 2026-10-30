# RESULTS — generated from `experiments/out/results.csv`

JDK: 25.0.5+8-LTS  
OS: Linux 7.2.11-arch1-1  
Trials per memory cell: 200

Every memory trial carries a positive control (unwiped canary) and a negative control. An INVALID trial is not a pass. `NOT_CHECKABLE` is not a pass.

## Memory matrix

| collector | mode | valid | target FOUND (false assurance) | rate | Wilson 95% CI | positive control FOUND |
|---|---|---|---|---|---|---|
| G1 | HOT | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| G1 | MOVE | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| G1 | WIPE | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| Parallel | HOT | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| Parallel | MOVE | 200 | 200 | 1.000 | [0.981, 1.000] | 1.000 |
| Parallel | WIPE | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| Serial | HOT | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| Serial | MOVE | 200 | 200 | 1.000 | [0.981, 1.000] | 1.000 |
| Serial | WIPE | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| Shenandoah | HOT | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| Shenandoah | MOVE | 200 | 200 | 1.000 | [0.981, 1.000] | 1.000 |
| Shenandoah | WIPE | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| ZGC | HOT | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |
| ZGC | MOVE | 200 | 1 | 0.005 | [0.001, 0.028] | 1.000 |
| ZGC | WIPE | 200 | 0 | 0.000 | [0.000, 0.019] | 1.000 |

## File matrix

| method | trials | logical result | note |
|---|---|---|---|
| crypto | 200 | 200/200 | raw-media residue NOT_CHECKABLE without an image |
| delete-only | 200 | 200/200 | raw-media residue NOT_CHECKABLE without an image |
| overwrite | 200 | 200/200 | raw-media residue NOT_CHECKABLE without an image |

## Tamper matrix

| mutation | trials | detected | rate |
|---|---|---|---|
| backdate | 200 | 200 | 1.000 |
| delete | 200 | 200 | 1.000 |
| edit | 200 | 200 | 1.000 |
| fork | 200 | 200 | 1.000 |

## Overhead

| method | size | median ms |
|---|---|---|
| overwrite | 1MiB | 0 |
| crypto | 1MiB | 15 |
| overwrite | 16MiB | 4 |
| crypto | 16MiB | 229 |
| overwrite | 64MiB | 18 |
| crypto | 64MiB | 231 |

## Limits

User-space Java cannot verify the SSD flash translation layer, bad-block pools, controller-held copies, journal copies, snapshots, or backups. These are logical-level results. The witness is a local key, not an independent party. No result here is a physical-erasure guarantee.
