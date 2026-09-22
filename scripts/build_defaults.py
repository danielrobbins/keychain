# SPDX-License-Identifier: GPL-3.0-only
"""Write package defaults into build output, never into the source checkout."""

import argparse
from pathlib import Path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("activation", choices=("prompt", "immediate"))
    args = parser.parse_args()
    args.output.write_text(
        f'# SPDX-License-Identifier: GPL-3.0-only\nDEFAULT_ACTIVATION = "{args.activation}"\n',
        encoding="utf-8",
    )
