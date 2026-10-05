#!/bin/sh
# RootWatch Flatpak wrapper — run the bundled asar with the BaseApp's Electron.
exec electron /app/lib/rootwatch/app.asar "$@"
