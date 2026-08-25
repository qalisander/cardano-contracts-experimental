# Experimental Contracts for Cardano (Aiken)

A collection of reusable smart contract building blocks for Cardano, written in Aiken.

This repository follows a multi-package layout under `contracts/`, so each standard can evolve independently (for example: Access Control, ERC-721-style NFTs, vesting modules, and future utilities).

## Usage

### Install Aiken

Follow the Aiken installation guide:

- https://aiken-lang.org/installation-instructions

Then confirm your setup:

```sh
aiken --version
```

### Repository Layout

- `contracts/`: package catalog (one package per standard/module)
- `contracts/access/`: standalone Access Control package

Each package has its own:

- `aiken.toml`
- `lib/` (sources and tests)
- `validators/` (on-chain entrypoints)

### Run Checks

Run checks for the Access Control package:

```sh
cd contracts/access && aiken check
```

Run a specific test module in Access Control:

```sh
cd contracts/access && aiken check -m "tests/access_control_tests.{..}"
```

## Docs

Documentation is available in package READMEs and inline module comments.

Current package documentation:

- `contracts/access/README.md`

## Notes

This project aims to keep familiar OpenZeppelin-style APIs and conventions where practical, while adapting to Cardano and Aiken-specific constraints.

Because execution model, state representation, and validator patterns differ from other ecosystems, some modules may intentionally diverge from EVM or Move implementations.

As more standards are added, each package can be versioned, tested, and audited independently.
