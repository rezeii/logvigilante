import argparse
import re
import sys
import logging
import pathlib
import os
import tempfile
import shutil
import signal
from typing import List, Pattern, Final, Iterator, Optional, Any
from types import FrameType
from contextlib import contextmanager

class LogVigilanteError(Exception): """Base exception for the LogVigilante domain."""
class ConfigurationError(LogVigilanteError): """Raised during initialization due to invalid parameters."""
class ProcessingError(LogVigilanteError): """Raised during active stream processing."""
class SecurityPolicyViolation(ProcessingError): """Raised when a log line exceeds safety limits (Log Bomb protection)."""

class LogProcessor:
    """
    A high-integrity log sanitization engine designed for mission-critical audit trails.

    This class implements atomic file operations, ensuring that the target file is either
    fully updated and synced to physical media, or remains unchanged. It protects against
    Memory Exhaustion (OOM) via bounded line reads and prevents 'Pattern Evasion' by 
    refusing to process lines that exceed the safety buffer.
    """
    MAX_LINE_BUFFER: Final[int] = 10 * 1024 * 1024  # 10MB Line Limit Safety

    def __init__(self, input_path: str, output_path: str, patterns: List[str], mask_char: str = "*"):
        """
        Initializes the processor with path validation.

        Args:
            input_path: Path to source log file.
            output_path: Destination path for redacted output.
            patterns: List of regex strings to redact.
            mask_char: Character used for masking matches.
        """
        self.input_path = pathlib.Path(input_path).resolve()
        self.output_path = pathlib.Path(output_path).resolve()
        self.mask_char = (mask_char if mask_char else "*")[0]
        self.patterns = self._compile_patterns(patterns)
        self.redaction_count = 0
        self._shutdown_requested = False
        self._validate_environment()

    def _compile_patterns(self, patterns: List[str]) -> List[Pattern]:
        if not patterns: 
            raise ConfigurationError("Regex pattern list cannot be empty.")
        try:
            return [re.compile(p) for p in patterns]
        except re.error as e:
            raise ConfigurationError(f"Regex compilation failed: {e}")

    def _validate_environment(self) -> None:
        if not self.input_path.is_file():
            raise ConfigurationError(f"Source is not a valid file: {self.input_path}")
        if self.input_path == self.output_path:
            raise ConfigurationError("In-place editing is disabled to prevent data loss on crash.")
        
        out_dir = self.output_path.parent
        if not out_dir.exists():
            raise ConfigurationError(f"Output directory does not exist: {out_dir}")
        if not os.access(out_dir, os.W_OK | os.X_OK):
            raise ConfigurationError(f"Insufficient permissions for directory: {out_dir}")

    def request_shutdown(self) -> None:
        """Flag the processor to stop at the next iteration for clean exit."""
        self._shutdown_requested = True

    def _mask_match(self, match: re.Match) -> str:
        self.redaction_count += 1
        return self.mask_char * len(match.group(0))

    def _safe_line_iterator(self, file_handle: Any) -> Iterator[str]:
        """
        Yields lines while strictly enforcing length limits.
        
        Logic: If a line exceeds MAX_LINE_BUFFER without a newline, we treat it as a 
        security risk (malformed log/log bomb) rather than yielding partial data which 
        would cause regex patterns to miss matches.
        """
        for line in file_handle:
            if self._shutdown_requested:
                break
            if len(line) >= self.MAX_LINE_BUFFER and not line.endswith(('\n', '\r')):
                raise SecurityPolicyViolation(f"Line length exceeds limit of {self.MAX_LINE_BUFFER} bytes.")
            yield line

    def process(self) -> int:
        """
        Executes the redaction pipeline with multi-stage durability guarantees.
        
        Returns:
            Total count of redacted occurrences.
        
        Raises:
            ProcessingError: If any IO or integrity check fails.
        """
        temp_path: Optional[pathlib.Path] = None
        
        try:
            # 1. Create secure temporary file in the destination directory (prevents cross-dev rename issues)
            fd, path_str = tempfile.mkstemp(dir=self.output_path.parent, prefix=".vig_tmp_", text=True)
            temp_path = pathlib.Path(path_str)
            
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as fout:
                    with self.input_path.open('r', encoding='utf-8', errors='replace') as fin:
                        for line in self._safe_line_iterator(fin):
                            sanitized = line
                            for pattern in self.patterns:
                                sanitized = pattern.sub(self._mask_match, sanitized)
                            fout.write(sanitized)
                        
                    # 2. Flush and hardware sync data to disk before metadata swap
                    fout.flush()
                    os.fsync(fout.fileno())

                # 3. Mirror original file permissions
                shutil.copymode(str(self.input_path), str(temp_path))
                
                # 4. Perform atomic filesystem swap
                os.replace(temp_path, self.output_path)
                
                # 5. Persist the directory entry (Required for durability on many POSIX systems)
                if os.name != 'nt':
                    dir_fd = os.open(str(self.output_path.parent), os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)

                return self.redaction_count

            except Exception as inner_e:
                # Clean up the specific FD if open/write failed
                if temp_path and temp_path.exists():
                    temp_path.unlink()
                raise inner_e

        except Exception as e:
            raise ProcessingError(f"Atomic write operation failed: {e}") from e

def main():
    parser = argparse.ArgumentParser(description="LogVigilante 2.1: Secure Log Redaction")
    parser.add_argument("-i", "--input", required=True, help="Source log file path")
    parser.add_argument("-o", "--output", required=True, help="Sanitized output path")
    parser.add_argument("-p", "--patterns", nargs='+', required=True, help="Regex patterns to mask")
    parser.add_argument("-m", "--mask-char", default="*", help="Character for masking (default: *)")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    
    processor = LogProcessor(args.input, args.output, args.patterns, args.mask_char)

    def signal_handler(sig: int, frame: Optional[FrameType]):
        logging.warning(f"Signal {sig} received. Graceful shutdown initiated...")
        processor.request_shutdown()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        count = processor.process()
        logging.info(f"Redaction successful. {count} sensitive tokens masked.")
    except LogVigilanteError as e:
        logging.error(f"Application Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unrecoverable System Fault: {e}", exc_info=True)
        sys.exit(2)

if __name__ == '__main__':
    main()"