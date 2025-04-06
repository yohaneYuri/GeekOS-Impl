#! /nix/store/p6k7xp1lsfmbdd731mlglrdj2d66mr82-bash-5.2p37/bin/bash

# A helper that wraps `startProject` script
prev=`expr $1 - 1`
echo "moving from project${prev} to project$1"
startProject project$1 $GEEKOS_HOME/src project${prev}