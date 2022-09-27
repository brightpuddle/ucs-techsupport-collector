import sys

import pytermgui as ptg

with ptg.alt_buffer():
    root1 = ptg.Container(ptg.Label("[bold]."))
    root.print()

    while True:
        root.handle_key(ptg.getch())
        root.print()
