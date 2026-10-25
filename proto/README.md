# The Phigon protocol

`phigon.v1` is the only wire contract between observers and the Phigon control
plane. The Go bindings in `go/gen` and the TypeScript bindings in
`src/generated` are generated from these files; never edit them by hand.

`buf generate` needs `protoc-gen-go` v1.36.11 and `protoc-gen-go-grpc` v1.6.2 on
your `PATH`, and `npm ci` for `protoc-gen-es`. `generated.sha256` records the
checksums of the generated files and CI fails when they do not match; see
[Changing the protocol](../CONTRIBUTING.md#changing-the-protocol) for the
commands.

## Privacy model

Every event envelope declares the highest `PrivacyClass` it contains. The
observer applies collection policy and redaction before serialization. The
control plane rejects a message whose declared class is not allowed by the
effective machine policy. A missing policy is fail-closed.

`CollectionPolicy` contains only sensitive-content switches and every protobuf
default is `false`. The configured metadata profile explicitly enables bounded
process, file-operation, network, and bounded browser-operation metadata on
both sides of the policy
intersection. Process identity, lifecycle state, timestamps, counters, safe
normalized summaries, and cryptographic resource digests are system or resource
metadata. Raw prompts, responses, reasoning, arguments, output, paths, URLs,
patches, environment values, and file/browser/network content require an
explicit switch.

`supervision.proto` defines session, boundary, stable process, gateway,
evidence, attribution, coverage, sensor health, and integrity messages. Source,
OS, and gateway claims remain separate `EvidenceReference` values. A derived
`AttributionContext` never replaces the event's original agent or session IDs.

`ActionGuardrailPolicy` applies only to Phigon-managed command, file, network,
browser, process, credential, agent-launch, and model-selection gateways. A policy receipt proves that the
machine loaded a digest and declares the capabilities it can mediate; it does
not prove OS-wide interception. Enforcement labels in the app must therefore
remain `not_received`, `received`, `rejected`, or `managed_gateway_only` unless independent
coverage evidence supports a stronger claim.

Each deny rule carries a maximum typed intervention: block the proposed action,
stop the exact offending agent process, or force-stop that exact process. Stop
controls require a current hosted administrator decision and a fresh exact
process-instance identity. Local Guardian controls are removed; policy delivery
alone is never evidence that termination occurred. Exact set restrictions stay
authoritative on the control plane and are included in its policy digest; the
observer wire copy is delivery state, not a rule evaluator.

## Wire limits

The ingress validator enforces these hard limits before publishing or storage:

| Field class | Maximum |
| --- | ---: |
| IDs and correlation keys | 128 bytes |
| Display names | 256 UTF-8 bytes |
| Safe event summary | 512 UTF-8 bytes |
| URL | 8 KiB |
| Prompt, response, reasoning, terminal chunk, file excerpt | 64 KiB |
| Tool arguments | 128 KiB |
| Tool output and Git patch | 256 KiB |
| Labels | 32 entries |
| Agent capabilities | 64 entries |
| Event envelope after protobuf encoding | 1 MiB |

Oversize metadata is rejected. Oversize policy-enabled content is truncated at
the observer, marked redacted, and never emitted as an unbounded field.

## Compatibility

- Field numbers are never reused.
- Removed fields are reserved.
- Unknown fields must survive decode/re-encode boundaries.
- Semantic schema revisions increment `EventEnvelope.schema_version`.
- Changes are add-only: `buf breaking` protects the released contract.
