#! /bin/sh
set -ex

lcov --list build/lcov/data/capture/all_targets.info  # debug before upload
coveralls-lcov build/lcov/data/capture/all_targets.info