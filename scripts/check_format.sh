#! /bin/bash

if [[ -z $CLANG_FORMAT ]]; then
	CLANG_FORMAT="clang-format"
fi


PATTERN=".*\\.\\(h\\|c\\|hpp\\|cpp\\)\$"

FILES="$(find lib -type f -print| grep "$PATTERN")"
FILES+=" $(find src -type f -print| grep "$PATTERN")"
FILES+=" $(find test -type f -print| grep "$PATTERN")"

for file in $FILES ; do
    eval "$CLANG_FORMAT -i ${file}"
done

INVALID_FORMAT_FILES=$(git diff --name-only | grep "$PATTERN")


if [ -z "$INVALID_FORMAT_FILES" ]; then
    echo "All the source files are correctly formated."
else
    echo "The following files are incorrectly formated:"
    echo "$INVALID_FORMAT_FILES"
    exit 1
fi