# Socket Library

High-performance, exception-driven socket toolkit inspired by *C Interfaces and Implementations*.

## Documentation

- [Release Notes](RELEASE_NOTES.md) – latest reliability/performance enhancements, including timeout APIs, DNS cancellation, and poll/pool optimisations.
- `.cursor/rules/` – authoritative coding, architectural, and module pattern guides enforced across the codebase.

## Building

```
cmake -S . -B build
cmake --build build -j
cmake --build build --target test
```

## License

See `LICENSE` (if provided) for usage details.

