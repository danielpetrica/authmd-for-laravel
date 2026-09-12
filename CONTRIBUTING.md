# Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Development

```bash
composer install
composer test
```

## Quality Gates

- `composer lint` — Pint + Rector
- `composer test:types` — PHPStan level max
- `composer test:type-coverage` — 100% type coverage
- `composer test:unit` — 100% unit test coverage
