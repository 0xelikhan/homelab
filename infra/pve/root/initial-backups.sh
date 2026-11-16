#!/bin/bash
O="--mode snapshot --compress zstd --prune-backups keep-last=1 --notes-template {{guestname}} --quiet 1"
vzdump 120 101 102 103 104 105 106 107 108 109 115 116 117 118 121 --storage sandisk-1tb $O
vzdump 111 112 114 --storage ssd-enclosure $O
echo "initial backups finished $(date)"
