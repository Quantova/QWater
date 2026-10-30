# QWater

QWater is a live production post quantum registry tool for water rights and allocations on the Quantova network. It proves the allocation, use reporting, transfer and revocation of water rights, and it lets any third party confirm that history without trusting the party that created it.

Only a salted cryptographic commitment is written to the chain. Right identities and holder details stay private on the systems of the party that holds them.

## What it records

1. allocate, an authority allocates an annual volume from a source in a basin to a holder.
2. use, a holder or meter operator reports the volume used in a period.
3. transfer, the holder transfers the right to another party.
4. revoke, an authority ends the right and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names.

## Install

```
npm install @quantovainc/qwater
```

## License

Apache-2.0 OR MIT
