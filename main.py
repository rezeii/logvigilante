import argparse
import re
import sys
import logging
import pathlib
import os
import tempfile
import shutil
import signal
from typing import List, Pattern, Final, Iterator, Optional
from types import FrameType

class LogVigilanteError(Exception): """Base exception for the LogVigilante domain."""
class ConfigurationError(LogVigilanteError): """Raised during initialization due to invalid parameters."""
class ProcessingError(LogVigilanteError): """Raised during active stream processing."""

class LogProcessor:
    """
    A high-integrity log sanitization engine.

    Features:
    - O(1) Memory: Processes files using chunked buffering.
    - Atomic Durability: Uses mkstemp + fsync + os.replace.
    - Metadata Preservation: Clones file mode/permissions from source to target.
    """
    CHUNK_SIZE: Final[int] = 1024 * 64  # 64KB Buffer
    MAX_LINE_BUFFER: Final[int] = 1024 * 1024 * 10  # 10MB Line Limit Safety

    def __init__(self, input_path: str, output_path: str, patterns: List[str], mask_char: str = "*"):
        self.input_path = pathlib.Path(input_path).resolve()
        self.output_path = pathlib.Path(output_path).resolve()
        self.mask_char = mask_char[0] if mask_char else "*"
        self.patterns = self._compile_patterns(patterns)
        self.redaction_count = 0
        self._interrupted = False
        self._validate_environment()

    def _compile_patterns(self, patterns: List[str]) -> List[Pattern]:
        if not patterns: raise ConfigurationError("No patterns provided.")
        try:
            return [re.compile(p) for p in patterns]
        except re.error as e:
            raise ConfigurationError(f"Invalid regex: {e}")

    def _validate_environment(self):
        if not self.input_path.is_file():
            raise ConfigurationError(f"Input missing: {self.input_path}")
        if self.input_path == self.output_path:
            raise ConfigurationError("In-place editing is forbidden for integrity.")
        out_dir = self.output_path.parent
        if not os.access(out_dir, os.W_OK | os.X_OK):
            raise ConfigurationError(f"Directory not writable: {out_dir}")

    def _mask_match(self, match: re.Match) -> str:
        self.redaction_count += 1
        return self.mask_char * len(match.group(0))

    def _safe_line_iterator(self, file_obj) -> Iterator[str]:
        """Yields lines while enforcing a maximum line length to prevent OOM."""
        while True:
            line = file_obj.readline(self.MAX_LINE_BUFFER)
            if not line: break
            yield line

    def process(self) -> int:
        temp_fd: Optional[int] = None
        temp_path: Optional[str] = None
        
        try:
            # Create temp file in the same partition
            temp_fd, temp_path = tempfile.mkstemp(dir=self.output_path.parent, prefix=".vigilante_")
            
            with self.input_path.open('r', encoding='utf-8', errors='replace') as fin, \
                 os.fdopen(temp_fd, 'w', encoding='utf-8') as fout:
                temp_fd = None # Handled by context manager
                
                for line in self._safe_line_iterator(fin):
                    sanitized = line
                    for pattern in self.patterns:
                        sanitized = pattern.sub(self._mask_match, sanitized)
                    fout.write(sanitized)
                
                fout.flush()
                os.fsync(fout.fileno())

            # Clone permissions from source to temp
            shutil.copymode(str(self.input_path), temp_path)
            
            # Atomic swap
            os.replace(temp_path, self.output_path)
            
            # Fsync parent directory to ensure metadata persistence (POSIX)
            if os.name != 'nt':
                parent_fd = os.open(str(self.output_path.parent), os.O_RDONLY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)

            return self.redaction_count

        except Exception as e:
            if temp_path and os.path.exists(temp_path):
                try: os.remove(temp_path) 
                except: pass
            if temp_fd is not None: 
                try: os.close(temp_fd)
                except: pass
            raise ProcessingError(f"Fault during stream: {e}")

def main():
    parser = argparse.ArgumentParser(description="LogVigilante 2.0")
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-p", "--patterns", nargs='+', required=True)
    parser.add_argument("-m", "--mask-char", default="*")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    def signal_handler(sig, frame):
        logging.warning("Interrupt received. Cleaning up...")
        sys.exit(130)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        proc = LogProcessor(args.input, args.output, args.patterns, args.mask_char)
        count = proc.process()
        logging.info(f"Processing complete. Redactions: {count}")
    except LogVigilanteError as e:
        logging.error(e)
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected system fault: {e}")
        sys.exit(2)

if __name__ == '__main__':
    main()"