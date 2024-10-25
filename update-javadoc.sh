#!/bin/bash
rm -rf docs
mvn clean javadoc:javadoc
mv target/reports/apidocs docs
git config --global user.email "gha@github.com"
git config --global user.name "GHActionBot"
git add --all
git commit -am "Sync javadoc."
git push
exit 0