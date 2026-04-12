# LogVigilante Architecture

## 1. Design Philosophy
LogVigilante is built on the **Fail-Fast** principle. The application is architected to crash as early as possible if prerequisites are not met, preventing partial file writes or silent data corruption.

## 2. Layered Execution Model

### A. Initialization Layer (Validation)
- **Regex Validation**: All patterns provided via CLI are compiled into `re.Pattern` objects during instantiation. If any pattern is invalid, a `ConfigurationError` is raised immediately.
- **Filesystem Verification**: 
    - Input file existence and file-type check.
    - Output directory writability and existence.
    - Collision detection (Input != Output).
- **State Initialization**: Redaction counters and stream pointers are initialized.

### B. Processing Layer (Streaming)
- **O(1) Space Complexity**: The application uses a generator-based line streamer (`for line in fin`). It never loads the entire file into RAM, making it suitable for multi-gigabyte log files.
- **Regex Subsitution**: Iterates through compiled patterns for each line. It uses a callback-based substitution to track metrics (redaction counts) in real-time.
- **Encoding Safety**: Input is read with `errors='replace'` to prevent process termination on minor encoding artifacts common in corrupted logs.

### C. Resource Management Layer
- **Context Managers**: Uses `with` statements to ensure that file descriptors are closed even if a `ProcessingError` (e.g., Disk Full) occurs during execution.

## 3. Error Hierarchy
- `LogVigilanteError`: Base class for all domain-specific exceptions.
- `ConfigurationError`: Raised during the Initialization Layer. Indicates user error (invalid paths, bad regex).
- `ProcessingError`: Raised during the Processing Layer. Indicates system-level failures (I/O, Permissions lost mid-stream).

## 4. Operational Metrics
The processor tracks the total number of masked occurrences, providing a summary upon successful completion to facilitate automated audit trails.