#! /bin/bash
set -e


: "${CLANG_TIDY:=$(command -v clang-tidy)}"
: "${STATIC_ANALYSIS_DIR:=static_analysis}"

echo "Using $CLANG_TIDY"


if [ ! -f $STATIC_ANALYSIS_DIR/compile_commands.json ]; then
    echo "Generate the compile commands"

    mkdir -p $STATIC_ANALYSIS_DIR
    (
        cd $STATIC_ANALYSIS_DIR
        # For the static analysis, only focus on an AES NI-enabled target
        CMAKE_PREFIX_PATH=${HOME}/deps CFLAGS="-maes -DWITH_OPENSSL" CXXFLAGS="-maes -DWITH_OPENSSL" cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
        make grpc_gen
    )
fi

set +e

EXCLUDE_PATTERN="*.pb.(h|cc)" # The 'a^' regexp matches nothing

FILES="$(find lib src -name '*.cpp' -or -name '*.c' | grep -ve "$EXCLUDE_PATTERN" | tr '\n' ' ')"

TIDY_COMMAND="$CLANG_TIDY -p=$STATIC_ANALYSIS_DIR $FILES"
echo "$TIDY_COMMAND"
eval "$TIDY_COMMAND"
