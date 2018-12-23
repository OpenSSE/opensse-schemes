#! /bin/bash
set -e

: "${CPPCHECK:=$(command -v cppcheck)}"
: "${STATIC_ANALYSIS_DIR:=static_analysis}"

bold=$(tput bold)
normal=$(tput sgr0)
red=$(tput setaf 1)

CPPCHECK_TEMPLATE="${bold}{file}:{line}${normal}\\n${bold}${red}error: ${normal}${bold}{severity}({id}): {message}${normal}\\n{code}"

CPPCHECK_OPTIONS="--std=c++11 --force  --enable=warning,performance,portability,style --error-exitcode=1 --report-progress  --inline-suppr --template=\"$CPPCHECK_TEMPLATE\""

echo "Using $CPPCHECK"

INCLUDES="-Ilib  -Ilib/include"

COMMAND="$CPPCHECK lib $INCLUDES $CPPCHECK_OPTIONS"

set +e

echo "$COMMAND"

eval "$COMMAND"