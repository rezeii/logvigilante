## 1. Atomic Integrity Model
LogVigilante employs an 'Atomic-Commit' write strategy. Instead of writing directly to the target output (which could leave a half-finished file on disk if the process is killed or the disk fills up), it utilizes `mkstemp` to create a hidden temporary file in the same filesystem volume. Only upon a successful stream and an explicit `fsync()` is the file renamed to the target via `os.replace`. This ensures that either the full sanitized file exists, or the previous state remains untouched.

## 2. Resource & Complexity Management
- **Memory Complexity**: O(1). The application uses a generator-based line iterator. This allows processing of multi-terabyte logs on systems with minimal RAM.
- **I/O Optimization**: Manual flushing and OS synchronization (`fsync`) are used to ensure the kernel buffers are committed to physical storage, vital for audit log integrity.
- **Encoding Resilience**: Uses `errors='replace'` on input streams. This prevents the utility from crashing when encountering illegal byte sequences often found in binary-corrupted text logs.

## 3. Strict Permission Verification
The 'Fail-Fast' principle is extended to filesystem metadata. The app validates `os.R_OK` for inputs and `os.W_OK | os.X_OK` for output directories before initiating any heavy I/O operations, catching permission errors early in the lifecycle.

## 4. Exception Mapping
- `LogVigilanteError`: Root domain exception.
- `ConfigurationError`: Pre-flight failure (e.g., regex syntax, permission denied, path collision).
- `ProcessingError`: Mid-flight failure (e.g., Disk Full, hardware I/O error, SIGTERM during stream).