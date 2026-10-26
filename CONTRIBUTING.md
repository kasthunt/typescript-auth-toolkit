# Contributing

Use Node.js 22 or 24, run `npm ci`, then `npm run check` and `npm run test:coverage`.

Keep utilities small and independent of frameworks or applications. Add a regression test for changed behaviour and explain any change to an exported contract. Protocol changes should include independently verifiable vectors.

Use generated or clearly synthetic fixtures. Do not commit environment files, keys, real account details, private source code, internal infrastructure names, or customer data. Follow [SECURITY.md](SECURITY.md) for vulnerability reports.
