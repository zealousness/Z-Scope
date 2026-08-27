# Demo Parser

## API contract

`parse_byte(uint8_t value)` accepts values in the inclusive range **0..255**.
Callers must reject values outside that range before invoking the API.

The parser returns a status code and does not take ownership of the input
buffer.

See [module documentation](docs/module.md).
