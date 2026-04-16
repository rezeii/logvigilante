import argparse
import re
import sys
import logging
import pathlib
import os
import tempfile
import shutil
import signal
import errno
from typing import List, Pattern, Final, Iterator, Optional, Any, Union
from types import FrameType

class LogVigilanteError(Exception): """Base exception for the LogVigilante domain."""
class ConfigurationError(LogVigilanteError): """Raised during initialization due to invalid parameters."""
class ProcessingError(LogVigilanteError): """Raised during active stream processing."""
class SecurityPolicyViolation(ProcessingError): """Raised when a log line exceeds safety limits."""

class LogProcessor:
    """
    A high-integrity log sanitization engine designed for mission-critical audit trails.

    Attributes:
        MAX_LINE_BUFFER (int): The maximum allowed bytes per line (10MB) to prevent OOM.
        CHUNK_SIZE (int): Buffer size for IO operations.
    """
    MAX_LINE_BUFFER: Final[int] = 10 * 1024 * 1024
    CHUNK_SIZE: Final[int] = 64 * 1024

    def __init__(self, input_path: str, output_path: str, patterns: List[str], mask_char: str = "*") -> None:
        """
        Initializes the processor with rigorous path resolution and pattern compilation.

        Args:
            input_path: Source log file.
            output_path: Destination for redacted content.
            patterns: List of regex strings to mask.
            mask_char: The character used to obscure sensitive data.

        Raises:
            ConfigurationError: If paths are invalid or patterns cannot be compiled.
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
            raise ConfigurationError("In-place editing is prohibited to prevent data corruption.")
        
        out_dir = self.output_path.parent
        if not out_dir.exists():
            raise ConfigurationError(f"Output directory does not exist: {out_dir}")
        if not os.access(out_dir, os.W_OK | os.X_OK):
            raise ConfigurationError(f"Insufficient directory permissions: {out_dir}")

    def request_shutdown(self) -> None:
        """Triggers a graceful exit by setting the internal shutdown flag."""
        self._shutdown_requested = True

    def _mask_match(self, match: re.Match) -> str:
        self.redaction_count += 1
        return self.mask_char * len(match.group(0))

    def _safe_readline_iterator(self, file_handle: Any) -> Iterator[str]:
        """
        Reads lines using a hard limit. Unlike standard iterators, this prevents
        loading massive single-line log bombs into memory.
        """
        while not self._shutdown_requested:
            line = file_handle.readline(self.MAX_LINE_BUFFER + 1)
            if not line:
                break
            if len(line) > self.MAX_LINE_BUFFER:
                raise SecurityPolicyViolation("Line length exceeds the safety threshold; possible log bomb detected.")
            yield line

    def process(self) -> int:
        """
        Executes the redaction pipeline with multi-stage durability and atomicity.

        Returns:
            int: Total count of redacted occurrences.

        Raises:
            ProcessingError: On IO failure, permission error, or integrity check failure.
        """
        temp_path: Optional[pathlib.Path] = None
        try:
            fd, path_str = tempfile.mkstemp(dir=self.output_path.parent, prefix=".vig_tmp_", text=True)
            temp_path = pathlib.Path(path_str)
            
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as fout:
                    with self.input_path.open('r', encoding='utf-8', errors='replace') as fin:
                        for line in self._safe_readline_iterator(fin):
                            sanitized = line
                            for pattern in self.patterns:
                                sanitized = pattern.sub(self._mask_match, sanitized)
                            fout.write(sanitized)
                        
                    fout.flush()
                    os.fsync(fout.fileno())

                shutil.copymode(str(self.input_path), str(temp_path))
                
                try:
                    os.replace(temp_path, self.output_path)
                except OSError as e:
                    if e.errno == errno.EXDEV:
                        raise ProcessingError("Atomic move failed across device boundaries.") from e
                    raise
                
                if os.name != 'nt':
                    dir_fd = os.open(str(self.output_path.parent), os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)

                return self.redaction_count

            except Exception:
                if temp_path and temp_path.exists():
                    temp_path.unlink()
                raise

        except Exception as e:
            if isinstance(e, LogVigilanteError): raise
            raise ProcessingError(f"Atomic operation failed: {e}") from e

def main():
    parser = argparse.ArgumentParser(description="LogVigilante: Atomic Log Redaction")
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-p", "--patterns", nargs='+', required=True)
    parser.add_argument("-m", "--mask-char", default="*")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
    
    try:
        processor = LogProcessor(args.input, args.output, args.patterns, args.mask_char)

        def signal_handler(sig: int, frame: Optional[FrameType]):
            logging.warning(f"Received signal {sig}. Aborting stream safely...")
            processor.request_shutdown()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        count = processor.process()
        logging.info(f"Redaction complete. {count} sensitive occurrences masked.")
    except LogVigilanteError as e:
        logging.error(f"Critical failure: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unexpected system fault: {e}", exc_info=True)
        sys.exit(2)

if __name__ == '__main__':
    main()"