# Radiant (RXD) support

This fork now has the first native Radiant support layer.

## Implemented

- Configurable block-header PoW through `coin` and `pow_algo`.
- Bitcoin/BCH remains the default (`sha256d`).
- Radiant uses double SHA-512/256 (`sha512_256d`).
- Bitcoin-style SHA-256d transaction IDs and Merkle trees are unchanged.
- `radaddr:` P2PKH/P2SH payout addresses are converted into coinbase scripts.
- All local, remote, node and trusted-server block-header validation paths use
  the selected PoW algorithm.
- A unit test validates SHA-512/256, double SHA-512/256, and the official
  Radiant genesis block header hash.

## Configuration

Copy `ckpool-rxd.conf`, then replace the RPC credentials and payout addresses.
The `btcaddress` key is retained for CKPool compatibility even when it contains
an RXD address.

```json
"coin": "radiant",
"pow_algo": "sha512_256d"
```

`coin: "radiant"` selects the same algorithm automatically. Keeping both
settings in the sample config makes an accidental algorithm mismatch fail fast.

## Important status

This is the PoW and address foundation. Before production mining, the next
validation stage must run against a synchronized Radiant node and a real RXD
miner to confirm its exact `getblocktemplate`, Stratum notify, share submission,
and `submitblock` behavior. Do not point production hashrate at this build until
an accepted low-difficulty testnet/regtest share and block have been observed.
