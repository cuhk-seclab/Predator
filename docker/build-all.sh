#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

python3 ${DIR}/checkout.py

if [[ -z ${1} ]]; then
    builds=( "base" "php7" )
else
    builds=( "$@" )
fi

impltypes=( "direct")

buildtypes=( "build" "run" )

for b in "${builds[@]}"; do
    for btype in "${buildtypes[@]}"; do
        for itype in "${impltypes[@]}"; do
            if docker build -t witcher/${itype}${b}${btype} -f "${DIR}/${itype}${b}${btype}.Dockerfile" "${DIR}/../${b}"; then
                printf "\033[32mSucessfully built ${itype}${b}${btype} \033[0m\n"
            else
                printf "\033[31mFailed to build ${itype}${b}${btype} \033[0m\n"
                exit 191
            fi
            if [[ "$b" == 'base' && "$btype" == 'build' ]]; then
                docker build -t witcher/build-widash-x86 -f "${DIR}/build-widash-x86.dockerfile" "${DIR}/../${b}"
            fi
        done
    done

done

