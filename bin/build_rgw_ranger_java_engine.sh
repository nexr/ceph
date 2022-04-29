#!/usr/bin/env bash
#
# File:        build_rgw_ranger_java_engine.sh
#
# Description: A utility script that builds rgw ranger_java_engine
#
# Examples:    To use, simply do:
#
#                  pushd $GIT_DIR ; bin/build_rgw_ranger_java_engine.sh; popd
#
#              where $GIT_DIR is the root of your git superproject.
#

# DEBUGGING
set -e
set -C # noclobber

pushd src/rgw/ranger/engine/java

mvn assembly:assembly -DdescriptorId=jar-with-dependencies
cp target/nesRangerEngine-1.0-SNAPSHOT-jar-with-dependencies.jar ../nesRangerEngine.jar

popd
