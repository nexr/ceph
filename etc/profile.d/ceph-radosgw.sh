if [ "x$JRE_HOME" == "x" ]; then
  export JRE_HOME=/usr/lib/jvm/jre
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:$JRE_HOME/lib/amd64/server:$JRE_HOME/lib/amd64:$JRE_HOME/lib:$JAVA_HOME/lib/server
