#! /bin/bash

if [[ -z $CLANG_FORMAT ]]; then
	CLANG_FORMAT="clang-format"
fi


PATTERN=".*\\.\\(h\\|c\\|hpp\\|cpp\\)\$"

FILES="$(git diff --name-only HEAD | grep "$PATTERN")"
FILES_CACHED="$(git diff --cached --name-only HEAD | grep "$PATTERN")"

echo "Formated files: " "$FILES" "$FILES_CACHED"

for file in $FILES ; do
    eval "$CLANG_FORMAT -i ${file}"
done
for file in $FILES_CACHED ; do
    eval "$CLANG_FORMAT -i ${file}"
done

