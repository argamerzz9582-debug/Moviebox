---
name: rex-file-format
description: Reverse engineering unknown binary file formats and inspecting AI model artifacts (GGUF, SafeTensors) via magic bytes, entropy, and structural offsets.
triggers: unknown file, file format, magic bytes, hex dump, proprietary format, binary structure, kaitai, imhex, gguf, safetensors
tools_required: python3, file, xxd, strings
---

# REX Unknown File Format & AI Model Metadata Skill

## Supported Targets
Unknown binary blobs, proprietary archives, SQLite databases, and AI model files (`GGUF`, `SafeTensors`).

## Headless Workflow
1. **Structural & Entropy Profile:** Run `python3 -m rex.cli target inspect "<file>"` to examine magic bytes, file size, and Shannon entropy.
2. **AI Model Artifacts (`GGUF` / `SafeTensors`):** Inspect header version, tensor counts, tensor shapes/dtypes, and metadata key-values read-only. Never claim model training data can be reconstructed from weights.
3. **Custom Binary Hypothesis:** Identify magic header, version fields, entry counts, offset tables (TOC), and length-prefixed strings. Mark format hypotheses as `Probable` until verified across multiple samples.
