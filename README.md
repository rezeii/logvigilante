# LogVigilante

LogVigilante is a production-grade CLI tool built for dev-ops and security auditors who need to sanitize sensitive information (PII, tokens, credit cards) from log files without loading entire files into RAM.

## Features
- **Memory Efficient**: Uses generator-based line streaming for multi-gigabyte log files.
- **Robust Error Handling**: Distinct exit codes and custom exceptions for configuration vs. runtime failures.
- **Regex Flexible**: Accepts multiple patterns via CLI.
- **Safety First**: Prevents in-place modification to avoid accidental data corruption.

## Usage
```bash
python log_vigilante.py -i access.log -o access_masked.log -p "\\d{3}-\\d{2}-\\d{4}" "token=[a-zA-Z0-9]+"
```