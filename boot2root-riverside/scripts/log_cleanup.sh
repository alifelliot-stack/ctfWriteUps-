#!/bin/bash
# Nightly log rollup for bob's app -- packs everything in app_logs/ for
# archival, then bob can hand the tarball to ops.
#
# VULNERABLE ON PURPOSE: this is the classic GTFOBins tar wildcard
# injection. Because the glob (*) is expanded by the shell before tar
# ever runs, any file bob creates inside app_logs/ becomes a literal
# argv token to tar -- including tar's own --checkpoint=1 and
# --checkpoint-action=exec=... options, which tar will happily obey.
# Since this script runs as root via sudo, so does whatever tar executes.
cd /home/bob/app_logs || exit 1
tar -czf /root/backups/app_logs_$(date +%s).tar.gz *
