#!/bin/sh

set -eux

FILENAME=$(grep -m1 value ${1:-main.md} | cut -d'"' -f2)

mkdir -p artifacts
perl -ne '$l=$_;$o=1 if $l=~/^<!---/;print $l if !$o;$o=0 if $l=~/^--->/;' < main.md > "./artifacts/${FILENAME}.md"
"${HOME}/go/bin/mmark" "./artifacts/${FILENAME}.md" > "./artifacts/${FILENAME}.xml"
perl -pi -e 's#<u format="char-num">##g;s#</u>##g' "./artifacts/${FILENAME}.xml"
"$(pip show xml2rfc|awk '/^Location:/{print $2}')/../../../bin/xml2rfc" --html "./artifacts/${FILENAME}.xml"
perl -pi -e 's/&amp;#/&#/g' "./artifacts/${FILENAME}.html"
