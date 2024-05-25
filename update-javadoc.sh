#!/bin/bash
JAVADOC_HOME=docs
cd $JAVADOC_HOME
rm -rf *
cd ..
mvn javadoc:javadoc
git config --global user.email "gha@github.com"
git config --global user.name "GHActionBot"
git commit -am "Sync javadoc."
git push
exit 0