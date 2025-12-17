import pathlib
import sys

try:
    import d810
except ImportError:
    # Ensure 'd810' is importable by adding the sibling 'src' directory to sys.path
    current_dir = pathlib.Path(__file__).resolve().parent
    src_path = current_dir.parent / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
