#!/usr/bin/env bash
#
# Runs the OpenPGP interoperability test suite of the Sequoia project against bcsop (and, for comparison, sqop, rsop,
# gosop and sop-openpgpjs with post-quantum support, and pgpainless-cli on Bouncy Castle Java).
#
# The suite is licensed under the GPL-3.0: nothing of it is committed to this repository. The script clones it at a
# pinned commit into tools/pgp-interop/results/oits-src (ignored by git) and builds it in Docker.
#
# Requirements: bash, .NET SDK 8+, Docker, perl, git. Works on Linux and on Windows (Git Bash with Docker Desktop).
#
# Usage: tools/pgp-interop/scripts/run-oits.sh [--retain REGEX] [--check] [--update]
#   --retain REGEX  run only the tests whose names match the (case insensitive) regular expression
#   --check         compare the results of bcsop with oits/expectations.json and fail on any difference
#   --update        write the results of bcsop to oits/expectations.json (review the difference before committing)

set -u

SUITE_URL="https://gitlab.com/sequoia-pgp/openpgp-interoperability-test-suite.git"
SUITE_COMMIT="a6da06a20ab2db77827de3a0035ab680b13f600a"
IMAGE="bc-interop-oits:${SUITE_COMMIT:0:7}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="$ROOT/tools/pgp-interop"
RESULTS="$TOOL/results"
RETAIN=""
CHECK=0
UPDATE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --retain) shift; RETAIN="$1" ;;
        --check) CHECK=1 ;;
        --update) UPDATE=1 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

if command -v cygpath > /dev/null 2>&1; then
    native() { cygpath -m "$1"; }
    export MSYS_NO_PATHCONV=1
else
    native() { echo "$1"; }
fi
log() { echo "$*" >&2; }

STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUT="$RESULTS/oits-out-$STAMP"
mkdir -p "$RESULTS" "$OUT"

# ---------------------------------------------------------------- the suite

if [ ! -d "$RESULTS/oits-src/.git" ]; then
    log "Cloning the test suite..."
    git clone --no-checkout "$SUITE_URL" "$(native "$RESULTS/oits-src")" || exit 2
fi
git -C "$(native "$RESULTS/oits-src")" cat-file -e "$SUITE_COMMIT^{commit}" 2> /dev/null \
    || git -C "$(native "$RESULTS/oits-src")" fetch origin "$SUITE_COMMIT" || exit 2
git -C "$(native "$RESULTS/oits-src")" checkout --quiet "$SUITE_COMMIT" || exit 2

# ---------------------------------------------------------------- the images

build_image() {
    local image="$1" dockerfile="$2"
    if ! docker image inspect "$image" > /dev/null 2>&1; then
        log "Building $image..."
        docker build -t "$image" -f "$(native "$TOOL/docker/$dockerfile")" "$(native "$TOOL/docker")" \
            > "$OUT/$image.build.log" 2>&1 || { log "docker build failed, see $OUT/$image.build.log"; exit 2; }
    fi
}
build_image "bc-interop-rsop:0.12.0" rsop.Dockerfile
build_image "bc-interop-gosop:1.1.0" gosop.Dockerfile
build_image "bc-interop-ojs:2.2.0" openpgpjs.Dockerfile
build_image "bc-interop-pgpainless:2.0.4" pgpainless.Dockerfile

log "Publishing bcsop for linux-x64..."
rm -rf "$RESULTS/oits-bcsop"
dotnet publish "$(native "$TOOL/BcSop/BcSop.csproj")" -c Release -r linux-x64 --self-contained \
    -o "$(native "$RESULTS/oits-bcsop")" -v q -nologo > "$OUT/publish.log" 2>&1 \
    || { log "publish failed, see $OUT/publish.log"; exit 2; }
cp "$TOOL/oits/config.json" "$RESULTS/oits-config.json"

log "Building $IMAGE (the first build compiles the suite and sqop and takes a while)..."
docker build -t "$IMAGE" -f "$(native "$TOOL/oits/Dockerfile")" "$(native "$RESULTS")" \
    > "$OUT/oits.build.log" 2>&1 || { log "docker build failed, see $OUT/oits.build.log"; exit 2; }

# ---------------------------------------------------------------- the run

ARGS=(--json-out=output/results.json --html-out=output/results.html --html-out-dir=output)
[ -n "$RETAIN" ] && ARGS+=("--retain-tests=$RETAIN")

log "Running the test suite..."
docker run --rm --pids-limit 2000000 -v "$(native "$OUT"):/test-suite/output" "$IMAGE" "${ARGS[@]}" \
    > "$OUT/run.log" 2>&1
rc=$?
if [ ! -s "$OUT/results.json" ]; then
    log "The test suite produced no results (exit code $rc), see $OUT/run.log"
    exit 2
fi
log "Results: $(native "$OUT")/results.html and results.json"

# ---------------------------------------------------------------- the comparison

# bcsop_results: one line per (test, producer, consumer) that involves bcsop, "KEY<TAB>SCORE", read from stdin
bcsop_results() {
    perl -MJSON::PP -e '
        binmode STDOUT, ":utf8"; local $/; my $data = decode_json(<STDIN>);
        foreach my $section (@{ $data->{results} }) {
            foreach my $test (@{ $section->{results} }) {
                foreach my $entry (@{ $test->{results} }) {
                    my $producer = $entry->{artifact}{producer};
                    foreach my $result (@{ $entry->{results} }) {
                        my $consumer = $result->{producer};
                        next unless $producer =~ /^bcsop/ || $consumer =~ /^bcsop/;
                        print "$section->{section} | $test->{title} | $producer -> $consumer\t$result->{score}\n";
                    }
                }
            }
        }' | sort -u
}

bcsop_results < "$OUT/results.json" > "$OUT/bcsop-results.tsv" \
    || { log "cannot read the results of bcsop"; exit 2; }
# the extraction is a pipeline into sort, which succeeds even when perl fails
[ -s "$OUT/bcsop-results.tsv" ] || { log "no results of bcsop could be read from results.json"; exit 2; }

if [ $UPDATE = 1 ]; then
    cp "$OUT/bcsop-results.tsv" "$TOOL/oits/expectations.tsv"
    log "Wrote oits/expectations.tsv"
fi

if [ $CHECK = 1 ]; then
    if diff <(tr -d '\r' < "$TOOL/oits/expectations.tsv" | sort) "$OUT/bcsop-results.tsv" > "$OUT/differences.txt"; then
        log "bcsop results match oits/expectations.tsv"
    else
        log "bcsop results differ from oits/expectations.tsv:"
        cat "$OUT/differences.txt" >&2
        exit 1
    fi
fi
exit 0
