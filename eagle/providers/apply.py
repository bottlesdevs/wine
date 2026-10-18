import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
patch = Path(__file__).with_name('events.patch')
header = Path(__file__).with_name('eagle_trace.h')
makefile = root / 'include/Makefile.in'
text = makefile.read_text()
if (root / 'include/eagle_trace.h').exists() or '\teagle_trace.h \\\n' in text:
    raise ValueError('Eagle providers are already applied; start with the Soda source tree')
if 'SOURCES = \\\n' not in text:
    raise ValueError('unsupported Wine include Makefile')
subprocess.run(['git', 'apply', '--check', str(patch)], cwd=root, check=True)
subprocess.run(['git', 'apply', str(patch)], cwd=root, check=True)
(root / 'include/eagle_trace.h').write_bytes(header.read_bytes())
makefile.write_text(text.replace('SOURCES = \\\n', 'SOURCES = \\\n\teagle_trace.h \\\n', 1))
print('Applied WinRT, DirectWrite, COM and observed mutex-wait providers')
